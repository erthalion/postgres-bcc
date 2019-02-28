# postgres-bcc

Set of scripts to get low-level information about PostgreSQL using
[bcc](https://github.com/iovisor/bcc/). The project so far is experimental, so
use it carefully. Tested with relatively old Linux kernel versions (4.14, 4.15)
and latest PostgreSQL 11, 12devel. Most of scripts are cross tested with
PostgreSQL statistic views or perf data. List of features:

### Lock tracing

Implemented in `lwlocks`, `sema`, `spin` to monitor LWLocks, PGSemaphore and
spin locks in PostgreSQL. Be aware that they are implemented as user probes,
which means that tracing involved context switching between kernel and
PostgreSQL and introduces an extra overhead.

### Network usage

Includes `net_per_query` and `net_per_dev` scripts to monitor how much data was
sent through network per PostgreSQL backend or network device.

### Cache

Contains `llcache_per_query` script to measure cache references/misses/hit for
LLC per PostgreSQL query.

### WAL

Implemented in `wal_per_query` and `wal_system` to measure how much data was
inserted into wal files per query and how much data was actually written from
filesystem point of view.

### Memory


`page_reclaim` shows how much memory was reclaimed during a tracing period
under the high memory pressure conditions.

`shmem` expose shared memory usage, including how much was mmap'ed
(copy-on-write), allocated via anonymous shared memory and dsm/dsa.

`working_set` allows to trace how frequently data buffers are accessed, and how
much of a database data is hot, somewhat hot or cold. This can be used to
estimate values for such parameters as `shared_buffers`.

### Filesystem

`io_timeouts` and `io_throttle` scripts allow to monitor how much io timeouts
or throttling was introduced due to Linux kernel writeback throttling.

`write_per_type` can be used for generic tracing and categorizing of any
writes, that are coming from PostgreSQL (it relies on stack traces, so provides
not higher level of accuracy, but anyway good for investigation).

### Miscellaneous

`futex` to measure a hash bucket size for futexes to see how pgsemaphore are
affected by lock contention (since every bucket is protected by spin lock).

`stacktrace` convenient tool to check if some particular linux kernel function
was called and corresponding event is happened.

`latency` shows the distribution of time, spent in PostgreSQL (between
`query_execute_start` and `query_execute_done`).

to run these script you need to have bcc installed and relatively new linux
kernel.

# Why

* this apporoach allows us to extract quite low-level information about
  postgresql and how does it interact with linux kernel. usually this kind of
  metrics are not tracked, but they could significantly help with reasoning
  about performance.

* postgres-bcc makes it easier to collect metrics per cgroup/k8s pod, which is
  crucial for performance investigation, but most of tools for resource
  monitoring doesn't provide this information.

* trying to explain benchmark results could be tricky, and this tool gives an
  insight on what's going on inside.

# examples

```
# run PostgreSQL inside a docker container, check network usage under pgbench
# insert workload. get postgres binary and container id using docker inspect
# postgres_test.

$ net_per_query.py bin/postgres -c $container_id
attaching...
listening...
detaching...

send
[16397:4026532567] copy pgbench_accounts from stdin: 16b
[16397:4026532567] alter table pgbench_accounts add primary key (aid): 96b
[16428:4026532567] postgres: backend 16428: 2k
[16397:4026532567] vacuum analyze pgbench_tellers: 128b
[16397:4026532567] postgres: backend 16397: 14k
[16397:4026532567] vacuum analyze pgbench_history: 128b
[16397:4026532567] vacuum analyze pgbench_accounts: 128b
[14921:4026532567] postgres: background writer   : 528b
[16397:4026532567] vacuum analyze pgbench_branches: 160b

receive
[16397:4026532567] copy pgbench_accounts from stdin: 16m
[16397:4026532567] postgres: backend 16397: 2m
[14924:4026532567] postgres: stats collector   : 67k
```

```
# run PostgreSQL inside a docker container, check how much wal was written
# under pgbench read-write workload.

$ wal_per_query.py bin/postgres -c $container_id
attaching...
listening...
detaching...

[6170:4026532567] insert into pgbench_history (tid, bid, aid, delta, mtime) values (50, 3, 592413, -1689, current_time: 79b
[6170:4026532567] update pgbench_accounts set abalance = abalance + 2519 where aid = 995333;: 289b
[6170:4026532567] insert into pgbench_history (tid, bid, aid, delta, mtime) values (86, 10, 117836, -1792, current_tim: 79b
[6170:4026532567] insert into pgbench_history (tid, bid, aid, delta, mtime) values (3, 3, 32554, 434, current_timestam: 79b
```

```
# Run PostgreSQL inside a docker container with memory limitations, put it
# under memory pressure with pgbench and check how much memory was reclaimed,
# white normal database functioning

$ page_reclaim.py

[7382] postgres: 928K
[7138] postgres: 152K
[7136] postgres: 180K
[7468] postgres: 72M
[7464] postgres: 57M
[5451] postgres: 1M
```
