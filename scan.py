import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager
import ipaddress
import itertools
import random
import secrets

import aiosqlite
import async_timeout
import mtrpacket
import tqdm.asyncio


@asynccontextmanager
async def mtr_clients(max_count):
    clients = await asyncio.gather(
        *[mtrpacket.MtrPacket().open() for _ in range(max_count)]
    )

    try:
        yield itertools.cycle(clients)
    finally:
        for client in clients:
            await client.close()


def probe_generator(mtr, ip_address, sem):
    probes = [{"host": ip_address, "ttl": ttl} for ttl in range(2, 5)]

    async def probe(timeout=1, **kwargs):
        try:
            # Using a semaphore here is important because otherwise the timeout
            # starts to tick when we enter this function
            async with sem, async_timeout.timeout(timeout):
                result = await mtr.probe(**kwargs)
        except asyncio.TimeoutError:
            result = mtrpacket.ProbeResult(False, "timeout", timeout * 1000, None, None)

        return (ip_address, kwargs["ttl"], result)

    return (probe(**probe_kwargs) for probe_kwargs in probes)


async def run(ips_to_scan):
    max_concurrency = min(100, len(ips_to_scan) * 5)

    sem = asyncio.Semaphore(max_concurrency)

    async with mtr_clients(max_count=max_concurrency) as clients:
        tasks = list(
            itertools.chain.from_iterable(
                probe_generator(client, ip_address, sem)
                for client, ip_address in zip(clients, ips_to_scan)
            )
        )
        random.shuffle(tasks)

        for task in tqdm.tqdm(
            asyncio.as_completed(tasks),
            desc="tracerouting",
            total=len(tasks),
        ):
            ip_address, ttl, probe = await task

            yield (
                ip_address,
                {
                    "ttl": ttl,
                    "result": probe.result,
                    "time_ms": probe.time_ms,
                    "responder": probe.responder,
                },
            )


async def batch_run(ips_to_scan):
    responses = defaultdict(lambda: [])

    async for ip_address, result in run(ips_to_scan):
        responses[ip_address].append(result)

    return responses


def random_ip(network: ipaddress.IPv4Network):
    random_prefix_length = random.randint(
        16,
        24,
    )

    random_subnet = random.choice(
        list(network.subnets(new_prefix=random_prefix_length))
    )

    return str(next(random_subnet.hosts()))


async def main():
    prefix_length = 20

    ips_to_scan = [
        random_ip(network)
        for network in tqdm.tqdm(
            ipaddress.ip_network("0.0.0.0/0").subnets(new_prefix=prefix_length),
            desc="ip selection",
            total=(2 ** prefix_length),
        )
    ]

    run_id = secrets.token_urlsafe(16)
    async with aiosqlite.connect("./results.db") as conn:
        await conn.execute("PRAGMA journal_mode = wal")
        await conn.execute("PRAGMA busy_timeout = 5000")

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS results (run_id, destination, ttl, result, time_ms, responder);
            """
        )

        i = 0
        async for ip_address, r in run(ips_to_scan):
            await conn.execute(
                "INSERT INTO results (run_id, destination, ttl, result, time_ms, responder) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    ip_address,
                    r["ttl"],
                    r["result"],
                    r["time_ms"],
                    r["responder"],
                ),
            )

            if i % 10000 == 0:
                await conn.commit()
            i += 1


if __name__ == "__main__":
    asyncio.run(main())
