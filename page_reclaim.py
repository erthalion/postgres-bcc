#!/usr/bin/env python
#
# stacktrace    Track provided event in the kernel and print user/kernel stack
#
# usage: stacktrace -e event_name


from __future__ import print_function
from time import sleep
from bcc import BPF, USDT

import argparse
import ctypes as ct
import signal
import sys

import utils


text = """
#include <linux/ptrace.h>

#define HASH_SIZE 2^14

struct key_t {
    int pid;
    //unsigned long nr_pages;
    char name[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(reclaim, struct key_t, long);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int probe_try_to_free_mem_cgroup_pages(struct pt_regs *ctx)
{
    struct key_t key = {};
    get_key(&key);

    //key.nr_pages = (unsigned long) PT_REGS_RC(ctx);

    //events.perf_submit(ctx, &key, sizeof(key));

    unsigned long zero = 0, *val;
    val = reclaim.lookup_or_init(&key, &zero);
    (*val) += (unsigned long) PT_REGS_RC(ctx);
}
"""


def attach(bpf, args):
    bpf.attach_kretprobe(event="try_to_free_mem_cgroup_pages", fn_name="probe_try_to_free_mem_cgroup_pages")


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_int), ("name", ct.c_char * 16)]


class DataDebug(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("nr_pages", ct.c_ulong),
                ("name", ct.c_char * 16)]


def run(args):
    print("Attaching...")
    debug = 4
    bpf = BPF(text=text, debug=debug)
    attach(bpf, args)
    exiting = False

    def print_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        name = event.name.decode("ascii")
        if not name.startswith("postgres"):
            return
        print("Event: pid {} name {} reclaimed {}".format(
            event.pid, event.name, event.nr_pages))

    bpf["events"].open_perf_buffer(print_event)

    print("Listening...")
    while True:
        try:
            sleep(1)
            # bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        if exiting:
            print("Detaching...")
            break

    for (k, v) in bpf.get_table('reclaim').items():
        size = utils.size(v.value * 4 * 1024)
        print("[{}] {}: {}".format(k.pid, k.name, size))


def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
