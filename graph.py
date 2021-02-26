import sqlite3

import graphviz
import pyasn
from tqdm import tqdm

asndb = pyasn.pyasn("./ipasn_20201227.dat")


def lookup_nodes_ptr(nodes):
    import asyncio
    import aiodns

    async def lookup_nodes(ips):
        ips = set(ips)

        resolver = aiodns.DNSResolver()  # ["8.8.8.8"]

        async def query(ip):
            try:
                result = await resolver.gethostbyaddr(ip)

                return ip, result.name
            except aiodns.error.DNSError:
                return ip, ip

        ip_to_dns = {}
        for task in tqdm(
            asyncio.as_completed([query(ip) for ip in ips]),
            total=len(ips),
        ):
            result = await task

            ip_to_dns[result[0]] = result[1]

        return ip_to_dns

    return asyncio.run(lookup_nodes((node[0] for node in nodes)))


def graph_from_results(nodes, edges, by="ttl"):
    dot = graphviz.Digraph()

    for a, b, ttl, count, percentage in edges:
        dot.edge(
            a,
            b,
            label=f"ttl:{ttl}\t{round(percentage*100, 0)}%",
            # label=f"ttl:{ttl}",
            weight=f"{count}",
        )

    node_by = {
        "ttl": {},
        "asn": {},
        "netblock": {},
    }

    node_ptr_lookup = lookup_nodes_ptr(nodes)
    for node, ttl in nodes:
        args = (node, node_ptr_lookup[node])

        node_by["ttl"].setdefault(ttl, []).append(args)

        asn, netblock = asndb.lookup(node)

        node_by["asn"].setdefault(asn, []).append(args)
        node_by["netblock"].setdefault(netblock, []).append(args)

    for key, nodes in node_by[by].items():
        with dot.subgraph(name=f"cluster_{by}:{key}") as c:
            c.attr(label=f"{by}:{key}")
            c.attr(style="filled", color="lightgrey")

            for args in nodes:
                c.node(*args)

    dot.render("out", format="svg", view=True)


def _init_conn(conn: sqlite3.Connection):
    conn.execute("PRAGMA journal_mode = wal")
    conn.execute("PRAGMA busy_timeout = 5000")

    min_count_per_ttl = 1
    min_percent_per_ttl = 0.01
    max_nodes_per_ttl = 100

    conn.execute(  # valid_nodes
        """
        CREATE TEMPORARY TABLE valid_nodes
        AS
            SELECT
                *
            FROM
                results
            WHERE
                responder IS NOT NULL
        """
    )
    conn.execute(  # top_n_per_ttl
        f"""
        CREATE TEMPORARY TABLE top_n_per_ttl
        AS
        WITH responders_by_ttl AS (
            SELECT
                responder,
                ttl,
                count(DISTINCT destination) AS _count,
                1.0 * count(DISTINCT destination) / sum(count(DISTINCT destination)) over(PARTITION BY ttl) AS _percentage
            FROM
                valid_nodes
            GROUP BY
                responder, ttl
        ), top_responders AS (
            SELECT
                responder,
                ttl,
                rank() OVER (PARTITION BY ttl ORDER BY _percentage DESC) AS _rank
            FROM responders_by_ttl
            WHERE
                    _count >= {min_count_per_ttl}
                AND _percentage >= {min_percent_per_ttl}
        )

        SELECT
            responder, ttl
        FROM
            top_responders
        WHERE
            _rank <= {max_nodes_per_ttl}
        """
    )


def main():
    with sqlite3.connect("./results.db") as conn:
        _init_conn(conn)

        nodes = list(
            conn.execute(
                """
            -- Create a fake "first" node
            SELECT
                '127.0.0.1' AS head,
                ttl - 1 AS ttl
            FROM
                valid_nodes
            WHERE
                ttl = (SELECT min(ttl) FROM valid_nodes)

            UNION ALL

            -- And include the rest of the real ones
            SELECT
                responder,
                ttl
            FROM
                top_n_per_ttl
                """
            )
        )

        edges = list(
            conn.execute(
                """
            WITH edges AS (
                -- First hop
                SELECT
                    '127.0.0.1' AS head,
                    responder AS tail,
                    ttl - 1 AS ttl
                FROM
                    valid_nodes
                WHERE
                    ttl = (SELECT min(ttl) FROM valid_nodes)

                UNION ALL

                -- Each hop
                SELECT
                    a.responder AS a,
                    b.responder AS b,
                    a.ttl
                FROM
                    valid_nodes a
                JOIN
                    valid_nodes b
                ON
                        a.run_id == b.run_id
                    AND a.ttl + 1 = b.ttl
                    AND a.destination = b.destination
                WHERE
                        (a.responder, a.ttl) IN top_n_per_ttl
                    AND (b.responder, b.ttl) IN top_n_per_ttl
            )

            SELECT
                head,
                tail,
                ttl,
                count(*),
                1.0 * count(*) / sum(count(*)) over(PARTITION BY ttl) AS _percentage
            FROM edges
            GROUP BY 1, 2, 3
            HAVING count(*) > 10
                """
            )
        )

    print("Graphing...")
    graph_from_results(nodes, edges, by="asn")


if __name__ == "__main__":
    main()
