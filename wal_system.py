#!/usr/bin/env python
#
# wal_system    Summarize amount of WAL written from the system point of view.
#               For that purpose we track pwrite and check stack trace to come
#               from wal write operation. Relying on stack trace may cause some
#               missing results, and if it's a significant issue, try
#               wal_per_query.
#
# usage: wal_system $PG_BIN/postgres [-d] [-p PID]

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

import utils


traditional = [
    (1024 ** 5, 'P'),
    (1024 ** 4, 'T'),
    (1024 ** 3, 'G'),
    (1024 ** 2, 'M'),
    (1024 ** 1, 'K'),
    (1024 ** 0, 'B'),
    ]

def size(bytes, system=traditional):
    """Human-readable file size.

    Using the traditional system, where a factor of 1024 is used::

    >>> size(10)
    '10B'
    >>> size(100)
    '100B'
    >>> size(1000)
    '1000B'
    >>> size(2000)
    '1K'
    >>> size(10000)
    '9K'
    >>> size(20000)
    '19K'
    >>> size(100000)
    '97K'
    >>> size(200000)
    '195K'
    >>> size(1000000)
    '976K'
    >>> size(2000000)
    '1M'

    Using the SI system, with a factor 1000::

    >>> size(10, system=si)
    '10B'
    >>> size(100, system=si)
    '100B'
    >>> size(1000, system=si)
    '1K'
    >>> size(2000, system=si)
    '2K'
    >>> size(10000, system=si)
    '10K'
    >>> size(20000, system=si)
    '20K'
    >>> size(100000, system=si)
    '100K'
    >>> size(200000, system=si)
    '200K'
    >>> size(1000000, system=si)
    '1M'
    >>> size(2000000, system=si)
    '2M'

    """
    for factor, suffix in system:
        if bytes >= factor:
            break
    amount = int(bytes/factor)
    if isinstance(suffix, tuple):
        singular, multiple = suffix
        if amount == 1:
            suffix = singular
        else:
            suffix = multiple
    return str(amount) + suffix


# load BPF program
bpf_text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#define HASH_SIZE 2^14
#define QUERY_LEN 100
#define STACK_STORAGE_SIZE 1024

struct key_t {
    int cpu;
    u32 pid;
    u64 namespace;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};

struct backend {
    int pid;
    char query[QUERY_LEN];
};

BPF_HASH(query_stacks, struct key_t, int);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

int syscall__pwrite(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    key.pid = bpf_get_current_pid_tgid();
    key.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    bpf_get_current_comm(&(key.name), sizeof(key.name));
    int len = (int) PT_REGS_PARM3(&ctx->regs);

    query_stacks.update(&key, &len);
    int zero = 0, *val;
    val = query_stacks.lookup_or_init(&key, &zero);
    (*val) += len;

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
    bpf.attach_uprobe(
        name=args.path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query",
        pid=args.pid)
    bpf.attach_uretprobe(
        name=args.path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query_finish",
        pid=args.pid)
    bpf.attach_kprobe(
        event="sys_pwrite64",
        fn_name="syscall__pwrite")


def print_stack(bpf, stack_id, tgid):
    if stack_id < 0:
        return

    stack = list(bpf.get_table("stack_traces").walk(stack_id))
    for addr in stack:
        print("        ", end="")
        print("%16x " % addr, end="")
        print("%s" % (bpf.sym(addr, tgid)))


def stack_from_wal(bpf, stack_id, tgid):
    if stack_id < 0:
        return False

    stack = list(bpf.get_table("stack_traces").walk(stack_id))
    for addr in stack:
        sym = bpf.sym(addr, tgid)
        if sym in {b"XLogBackgroundFlush", b"XLogFlush"}:
            return True

    return False


def pre_process(text, args):
    text = utils.replace_namespace(text, args)
    return text


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=pre_process(bpf_text, args), debug=debug)
    attach(bpf, args)
    exiting = False

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

    for (k, v) in bpf.get_table('query_stacks').items():
        if stack_from_wal(bpf, k.user_stack_id, k.pid):
            print("[{}:{}], {}, len: {}".format(
                k.pid, k.namespace, k.name, size(v.value)))
            print_stack(bpf, k.user_stack_id, k.pid)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Amount of WAL written from system point of view",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to PostgreSQL binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-c", "--container", type=str,
            help="trace this container only")
    parser.add_argument("-n", "--namespace", type=int,
            help="trace this namespace only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
        help="debug mode")
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
