#!/usr/bin/env python
#
# net_per_query  Summarize network usage per query/backend. For Linux, uses BCC.
#
# usage: net_per_query $PG_BIN/postgres [-d] [-p PID]

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

import utils

def get_pid_cmdline(pid):
    try:
        return open("/proc/{}/cmdline".format(pid)).read().strip()
    except FileNotFoundError as ex:
        return "postgres: backend {}".format(pid)


# load BPF program
bpf_text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#define HASH_SIZE 2^14
#define QUERY_LEN 100

struct key_t {
    int pid;
    char name[TASK_COMM_LEN];
    char query[QUERY_LEN];
};

struct backend {
    int pid;
    char query[QUERY_LEN];
};


BPF_HASH(send, struct key_t);
BPF_HASH(recv, struct key_t);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->pid = bpf_get_current_pid_tgid();
    struct backend *data = queries.lookup(&(key->pid));

    bpf_get_current_comm(&(key->name), sizeof(key->name));
    if (data != NULL)
        bpf_probe_read(&(key->query), QUERY_LEN, &(data->query));
}

int on_recv(struct pt_regs *ctx) {
    struct key_t key = {};
    get_key(&key);

    u64 zero = 0, *val;
    val = recv.lookup_or_init(&key, &zero);
    (*val) += PT_REGS_PARM3(ctx);

    return 0;
}

int on_send(struct pt_regs *ctx) {
    struct key_t key = {};
    get_key(&key);

    u64 zero = 0, *val;
    val = send.lookup_or_init(&key, &zero);
    (*val) += PT_REGS_PARM3(ctx);

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


def print_result(name, table):
    print(name)
    for (k, v) in table.items():
        if k.name == b"postgres":
            backend = k.query.decode("ascii") or get_pid_cmdline(k.pid)
            print("{} {}: {}".format(k.pid, backend, utils.size(v.value)))
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

    bpf.attach_kprobe(event="sys_sendto", fn_name="on_send")
    bpf.attach_kprobe(event="sys_send", fn_name="on_send")
    bpf.attach_kprobe(event="sys_recvfrom", fn_name="on_recv")
    bpf.attach_kprobe(event="sys_recv", fn_name="on_recv")


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

    print_result("Send", bpf.get_table('send'))
    print_result("Receive", bpf.get_table('recv'))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Summarize network usage per query/backend",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to PostgreSQL binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
        help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
