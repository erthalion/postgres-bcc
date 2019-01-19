# postgres-bcc

Set of scripts to get low-level information about PostgreSQL using
[bcc](https://github.com/iovisor/bcc/). The project so far is experimental, so
use it carefully. List of features:

* Lock tracing

Implemented in `lwlocks`, `sema`, `spin` to monitor LWLocks, PGSemaphore and
spin locks in PostgreSQL. Be aware that they are implemented as user probes,
which means that tracing involved context switching between kernel and
PostgreSQL and introduces an extra overhead.

* Network usage

Includes `net` and `netdev` scripts to monitor how much data was sent through
network per PostgreSQL backend or network device.

* System cache

Contains `query_cache` script to measure cache references/misses/hit for system
cache per PostgreSQL query.

* WAL

Implemented in `query_wal` and `wal` to measure how much data was inserted into
WAL files per query and how much data was actually written from filesystem
point of view.

* Heap

`writeback` script allow to monitor how much delay was introduced because of
writeback throttling by Linux kernel.

* Miscellaneous

    * `futex` to measure a hash bucket size for futexes to see how PGSemaphore are
      affected by lock contention (since every bucket is protected by spin lock).

    * `stacktrace` convenient tool to check if some particular Linux kernel
      function was called and corresponding event is happened.

To run these script you need to have bcc installed and relatively new Linux
kernel.

# Why

* Using bcc allows us to extract quite low-level information about PostgreSQL
  and how does it interact with Linux Kernel. Usually this kind of metrics are
  not tracked, but they could significantly help with reasoning about
  performance.

* postgres-bcc allows collecting metrics per cgroup/K8S pod, which is crucial
  for performance investigation, but most of tools for resource monitoring
  doesn't provide this information.

# Examples

```
# Run PostgreSQL inside a docker container, check network usage under pgbench
# insert workload. Get postgres binary and container id using docker inspect
# postgres_test.

$ net_per_query.py $PGBIN -c $CONTAINER_ID
Attaching...
Listening...
Detaching...

Send
[16397:4026532567] copy pgbench_accounts from stdin: 16B
[16397:4026532567] alter table pgbench_accounts add primary key (aid): 96B
[16428:4026532567] postgres: backend 16428: 2K
[16397:4026532567] vacuum analyze pgbench_tellers: 128B
[16397:4026532567] postgres: backend 16397: 14K
[16397:4026532567] vacuum analyze pgbench_history: 128B
[16397:4026532567] vacuum analyze pgbench_accounts: 128B
[14921:4026532567] postgres: background writer   : 528B
[16397:4026532567] vacuum analyze pgbench_branches: 160B

Receive
[16397:4026532567] copy pgbench_accounts from stdin: 16M
[16397:4026532567] postgres: backend 16397: 2M
[14924:4026532567] postgres: stats collector   : 67K
```

```
# Run PostgreSQL inside a docker container, check how much WAL was written
# under pgbench read-write workload.

$ wal_per_query.py $PGBIN -c $CONTAINER_ID
Attaching...
Listening...
Detaching...

[6170:4026532567] INSERT INTO pgbench_history (tid, bid, aid, delta, mtime) VALUES (50, 3, 592413, -1689, CURRENT_TIME: 79B
[6170:4026532567] UPDATE pgbench_accounts SET abalance = abalance + 2519 WHERE aid = 995333;: 289B
[6170:4026532567] INSERT INTO pgbench_history (tid, bid, aid, delta, mtime) VALUES (86, 10, 117836, -1792, CURRENT_TIM: 79B
[6170:4026532567] INSERT INTO pgbench_history (tid, bid, aid, delta, mtime) VALUES (3, 3, 32554, 434, CURRENT_TIMESTAM: 79B
```
