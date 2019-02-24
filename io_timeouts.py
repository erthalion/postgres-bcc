#!/usr/bin/env python
#
# io_timeouts   Track schedule_io_timeout inflicted by throttling from
#               writeback.
#
# usage: io_timeouts [-p PID] [-d]


from __future__ import print_function
from time import sleep
from bcc import BPF

import argparse
import ctypes as ct
import signal


text = """
#include <linux/ptrace.h>

#define HASH_SIZE 2^14
#define QUERY_LEN 100
#define LONG_MAX	((long)(~0UL>>1))
#define	MAX_SCHEDULE_TIMEOUT		LONG_MAX

struct key_t {
    int pid;
    long timeout;
    char name[TASK_COMM_LEN];
    char query[QUERY_LEN];
};

struct backend {
    int pid;
    char query[QUERY_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(io_timeout, struct key_t, long);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);

static inline __attribute__((always_inline)) int get_key(struct key_t* key) {
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

int probe_schedule_io_timeout(struct pt_regs *ctx)
{
    struct key_t key = {};
    int result = get_key(&key);

    key.timeout = (long) PT_REGS_PARM1(ctx);
    if (key.timeout == MAX_SCHEDULE_TIMEOUT)
    {
        key.timeout = -1;
    }

    events.perf_submit(ctx, &key, sizeof(key));
    if (result == 0)
        return 0;

    long zero = 0, *val;
    val = io_timeout.lookup_or_init(&key, &zero);
    (*val) += (long) PT_REGS_PARM1(ctx);

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


def attach(bpf, args):
    bpf.attach_uprobe(
        name=args.postgres_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query")
    bpf.attach_uretprobe(
        name=args.postgres_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query_finish")
    bpf.attach_kprobe(
        event="io_schedule_timeout",
        fn_name="probe_schedule_io_timeout")


# signal handler
def signal_ignore(sig, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("timeout", ct.c_long),
                ("name", ct.c_char * 16),
                ("query", ct.c_char * 100)]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("Event: pid {} query {} timeout {}".format(
        event.pid, event.query, event.timeout))


def run(args):
    print("Attaching...")
    debug = 4
    bpf = BPF(text=text, debug=debug)
    attach(bpf, args)
    exiting = False

    bpf["events"].open_perf_buffer(print_event)

    print("Listening...")
    while True:
        try:
            sleep(1)
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        if exiting:
            print("Detaching...")
            break

    for (k, v) in bpf.get_table('io_timeout').items():
        print("[{}] {}: {}".format(k.pid, k.query, v.value))


def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "-p", "--postgres_path", type=str,
        help="Path to the postgres binary")
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
