#!/usr/bin/env python
#
# stacktrace    Track provided event in the kernel and print user/kernel stack
#
# usage: stacktrace -e event_name


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
#define STACK_STORAGE_SIZE 1024

struct key_t {
    int pid;
    int result;
    char name[TASK_COMM_LEN];
    char query[QUERY_LEN];
};

struct backend {
    int pid;
    char query[QUERY_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->pid = bpf_get_current_pid_tgid();
    struct backend *data = queries.lookup(&(key->pid));

    bpf_get_current_comm(&(key->name), sizeof(key->name));

    if (data != NULL)
        bpf_probe_read(&(key->query), QUERY_LEN, &(data->query));
}

int probe_blk_throtl_bio(struct pt_regs *ctx)
{
    struct key_t key = {};
    get_key(&key);

    key.result = (int)PT_REGS_RC(ctx);

    if (key.result == 1)
        events.perf_submit(ctx, &key, sizeof(key));
}
"""


def attach(event_name, bpf, args):
    bpf.attach_kretprobe(
        event="blk_throtl_bio",
        fn_name="probe_blk_throtl_bio"
    )


# signal handler
def signal_ignore(sig, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("result", ct.c_int),
                ("name", ct.c_char * 16),
                ("query", ct.c_char * 100)]


def run(args):
    print("Attaching...")
    debug = 4
    bpf = BPF(text=text, debug=debug)
    attach(args.event, bpf, args)
    exiting = False

    def print_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        name = event.name.decode("ascii")
        if not name.startswith("postgres"):
            return
        print("Event: pid {} name {} query {} result {}".format(
            event.pid, event.name, event.query, event.result))

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


def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "-e", "--event", type=str,
        help="Event to trace")
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
