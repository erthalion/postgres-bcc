#!/usr/bin/python
#

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument(
    "-c", "--sample_period", type=int, default=100,
    help="Sample one in this many number of cache reference / miss events")
parser.add_argument(
    "-p", "--postgres_path", type=str,
    help="Path to the postgres binary")
parser.add_argument(
    "duration", nargs="?", default=10, help="Duration, in seconds, to run")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# load BPF program
bpf_text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#define HASH_SIZE 2^14
#define QUERY_LEN 100
#define STACK_STORAGE_SIZE 1024

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

BPF_HASH(query_stacks, u32, int);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

int syscall__pwrite(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    u32 pid = bpf_get_current_pid_tgid();
    int user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
    query_stacks.update(&pid, &user_stack_id);
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
        if sym == b"XLogBackgroundFlush":
            return True

    return False


if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
b.attach_uprobe(
    name=args.postgres_path,
    sym="exec_simple_query",
    fn_name="probe_exec_simple_query")
b.attach_uretprobe(
    name=args.postgres_path,
    sym="exec_simple_query",
    fn_name="probe_exec_simple_query_finish")
b.attach_kprobe(
    event="sys_pwrite64",
    fn_name="syscall__pwrite")

print("Running for {} seconds or hit Ctrl-C to end.".format(args.duration))

try:
    sleep(float(args.duration))
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, lambda signal, frame: print())

print("Detaching...")
print()

for (k, v) in b.get_table('query_stacks').items():
    if stack_from_wal(b, v.value, k.value):
        print("PID: {}".format(k.value))
        print_stack(b, v.value, k.value)
