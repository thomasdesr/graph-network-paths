import asyncio
import copy
import ipaddress
import random
import secrets

import aiosqlite
from tqdm.asyncio import tqdm

from aiotraceroute import aiotraceroute


async def gather_with_concurrency(tasks, concurrency):
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_task(task):
        async with semaphore:
            return await task

    return await asyncio.gather(*(sem_task(task) for task in tasks))


async def traceroute_ip(ip_addr, max_hops=10, timeout=1):
    return [
        (ip_addr, *res)
        async for res in aiotraceroute(ip_addr, max_hops=max_hops, timeout=timeout)
    ]


async def run(ips_to_scan, max_concurrency=250):
    ips_to_scan = copy.copy(ips_to_scan)
    random.shuffle(ips_to_scan)

    tasks = asyncio.Queue()
    results = asyncio.Queue()

    for ip_addr in tqdm(ips_to_scan, desc="creating tasks"):
        tasks.put_nowait(traceroute_ip(ip_addr))

    pbar = tqdm(desc="tracerouting", total=len(ips_to_scan))

    async def worker():
        while not tasks.empty():
            result = await tasks.get_nowait()

            for ip_address, ttl, result, next_addr, time_ms in result:
                results.put_nowait(
                    (
                        ip_address,
                        {
                            "ttl": ttl,
                            "time_ms": time_ms,
                            "result": result,
                            "responder": next_addr,
                        },
                    )
                )

            tasks.task_done()
            pbar.update(1)

    workers = [asyncio.create_task(worker()) for _ in range(max_concurrency)]

    while len(workers) != 0:
        _, workers = await asyncio.wait(workers, timeout=1)

        # Drain the queue
        while not results.empty():
            yield results.get_nowait()


def random_ip(network: ipaddress.IPv4Network):
    random_prefix_length = random.randint(
        max(16, network.prefixlen), min(27, network.prefixlen)
    )

    random_subnet = random.choice(
        list(network.subnets(new_prefix=random_prefix_length))
    )

    return str(next(random_subnet.hosts()))


async def main():
    scan_target = ipaddress.ip_network("0.0.0.0/0")
    prefix_length = 20

    ips_to_scan = [
        random_ip(network)
        for network in tqdm(
            scan_target.subnets(new_prefix=prefix_length),
            desc="ip selection",
            total=(2 ** (prefix_length - scan_target.prefixlen)),
        )
    ]

    run_id = secrets.token_urlsafe(16)
    async with aiosqlite.connect("./results.db", isolation_level=None) as conn:
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
