#!/usr/bin/env python
#
# latency    Track LWLocks in PostgreSQL and print wait/hold time
#            as a histogram. For Linux, uses BCC, eBPF.
#
# usage: latency $PG_BIN/postgres [-d] [-p PID] [-i INTERVAL]
#                                 [-c CONTAINER_ID] [-n NAMESPACE]

from __future__ import print_function
from time import sleep
from bcc import BPF

import argparse
import ctypes as ct
import signal
import sys

import utils


text = """
#include <linux/ptrace.h>

struct backend {
    u32 pid;
    u64 namespace;
    u64 start;
    u64 stop;
};

#define HASH_SIZE 2^14

BPF_PERF_OUTPUT(events);

BPF_HASH(latency, u32, struct backend, HASH_SIZE);

// Histogram of latency
BPF_HISTOGRAM(latency_hist, u64);

void probe_exec_simple_query(struct pt_regs *ctx, const char *query_string)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct backend key = {};

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    key.pid = pid;
    key.start = bpf_ktime_get_ns();
    latency.update(&pid, &key);
}

void probe_exec_simple_query_finish(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct backend *data = latency.lookup(&pid);
    if (data == NULL)
        return;

    u64 latency_time = now - data->start;
    data->stop = now;

    u64 latency_slot = bpf_log2l(latency_time / 1000);
    latency_hist.increment(latency_slot);
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


def pre_process(text, args):
    text = utils.replace_namespace(text, args)
    return text


def output(bpf, fmt="plain"):
    if fmt == "plain":
        print()
        latency_hist = bpf["latency_hist"]
        latency_hist.print_log2_hist("latency (us)")

    latency_hist.clear()


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=pre_process(text, args), debug=debug)
    attach(bpf, args)
    exiting = False

    print("Listening...")
    while True:
        try:
            sleep(args.interval)
            output(bpf)

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

    output(bpf)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Summarize cache references and misses by postgres backend",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to PostgreSQL binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-c", "--container", type=str,
            help="trace this container only")
    parser.add_argument("-n", "--namespace", type=int,
            help="trace this namespace only")
    parser.add_argument("-i", "--interval", type=int, default=5,
            help="after how many seconds output the result")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
