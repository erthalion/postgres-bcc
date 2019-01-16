#!/usr/bin/python
#
# query_cache.py Summarize cache references and cache misses by postgres backend.
#                Cache reference and cache miss are corresponding events defined in
#                uapi/linux/perf_event.h, it varies to different architecture.
#                On x86-64, they mean LLC references and LLC misses. Postgres
#                backend provides a query string. Based on llstat.py from bcc.
#                For Linux, uses BCC.
#
# SEE ALSO: perf top -e cache-misses -e cache-references -a -ns pid,cpu,comm
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
# usage: query_cache $PG_BIN/postgres [-d] [-c] [-p PID]

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep


# load BPF program
bpf_text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#define HASH_SIZE 2^14
#define QUERY_LEN 100

struct key_t {
    int cpu;
    int pid;
    char name[TASK_COMM_LEN];
    char query[QUERY_LEN];
};

struct backend {
    int pid;
    char query[QUERY_LEN];
};

BPF_HASH(ref_count, struct key_t);
BPF_HASH(miss_count, struct key_t);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);

static inline __attribute__((always_inline)) int get_key(struct key_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    struct backend *data = queries.lookup(&(key->pid));

    bpf_get_current_comm(&(key->name), sizeof(key->name));
    if (data != NULL)
    {
        bpf_probe_read(&(key->query), QUERY_LEN, &(data->query));
        return 1;
    }

    return 0;
}

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    int result = get_key(&key);

    if (result == 0)
        return 0;

    u64 zero = 0, *val;
    val = miss_count.lookup_or_init(&key, &zero);
    (*val) += ctx->sample_period;

    return 0;
}

int on_cache_ref(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    int result = get_key(&key);

    if (result == 0)
        return 0;

    u64 zero = 0, *val;
    val = ref_count.lookup_or_init(&key, &zero);
    (*val) += ctx->sample_period;

    return 0;
}

void probe_exec_simple_query(struct pt_regs *ctx, const char *query_string)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct backend data = {};
    data.pid = pid;
    bpf_probe_read(&data.query, QUERY_LEN, &(*query_string));
    queries.update(&pid, &data);
}

void probe_exec_simple_query_finish(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    queries.delete(&pid);
}
"""


# signal handler
def signal_ignore(signal, frame):
    print()


def attach(bpf, args):
    binary_path = args.path
    pid = args.pid

    bpf.attach_uprobe(
        name=binary_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query",
        pid=pid)
    bpf.attach_uretprobe(
        name=binary_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query_finish",
        pid=pid)
    bpf.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_MISSES,
        fn_name="on_cache_miss", sample_period=args.sample_period)
    bpf.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_REFERENCES,
        fn_name="on_cache_ref", sample_period=args.sample_period)


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=bpf_text, debug=debug)
    attach(bpf, args)
    exiting = False

    if args.debug:
        bpf["events"].open_perf_buffer(print_event)

    print("Listening...")
    while True:
        try:
            sleep(1)
            if args.debug:
                bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        if exiting:
            print()
            print("Detaching...")
            print()
            break

    miss_count = {}
    for (k, v) in bpf.get_table('miss_count').items():
        miss_count[(k.pid, k.cpu, k.name)] = v.value

    print('{:<8} {:<16} {:<100} {:<4} {:>12} {:>12} {:>6}%'.format(
        "PID", "NAME", "QUERY", "CPU", "REFERENCE", "MISS", "HIT"))
    tot_ref = 0
    tot_miss = 0
    for (k, v) in bpf.get_table('ref_count').items():
        try:
            miss = miss_count[(k.pid, k.cpu, k.name)]
        except KeyError:
            miss = 0
        tot_ref += v.value
        tot_miss += miss
        # This happens on some PIDs due to missed counts caused by sampling
        hit = (v.value - miss) if (v.value >= miss) else 0
        print('{:<8d} {:<16s} {:<100s} {:<4d} {:>12d} {:>12d} {:>6.2f}%'.format(
            k.pid, k.name.decode(), k.query.decode(), k.cpu, v.value, miss,
            (float(hit) / float(v.value)) * 100.0))

    if tot_ref != 0:
        print()
        print('Total References: {} Total Misses: {} Hit Rate: {:.2f}%'.format(
            tot_ref, tot_miss, (float(tot_ref - tot_miss) / float(tot_ref)) * 100.0))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Summarize cache references and misses by postgres backend",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to PostgreSQL binary")
    parser.add_argument(
        "-c", "--sample_period", type=int, default=100,
        help="Sample one in this many number of cache reference / miss events")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
