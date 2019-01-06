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

Consists of:

    * `futex` to measure a hash bucket size for futexes to see how PGSemaphore are
      affected by lock contention (since every bucket is protected by spin lock).

    * `stacktrace` convenient tool to check if some particular Linux kernel
      function was called and corresponding event is happened.

To run these script you need to have bcc installed and relatively new Linux
kernel.
