#!/usr/bin/env python
#
# page_reclaim  Track memory page reclaim by postgres processes,
#               globally or per cgroup/namespace
#
# usage: page_reclaim [-d] [-c CONTAINER_ID] [-n NAMESPACE] [-i INTERVAL]


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
    u64 namespace;
    STRUCT_NR_PAGES
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

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    STORE_NR_PAGES
    SUBMIT_EVENT

    unsigned long zero = 0, *val;
    val = reclaim.lookup_or_init(&key, &zero);
    (*val) += (unsigned long) PT_REGS_RC(ctx);

    return 0;
}
"""


PAGE_SIZE = 4 * 1024


def pre_process(text, args):
    text = utils.replace_namespace(text, args)
    if args.debug:
        text = text.replace("STRUCT_NR_PAGES", "unsigned long nr_pages;")
        text = text.replace(
            "STORE_NR_PAGES",
            "key.nr_pages = (unsigned long) PT_REGS_RC(ctx);"
        )
        text = text.replace(
            "SUBMIT_EVENT",
            "events.perf_submit(ctx, &key, sizeof(key));"
        )
    else:
        text = text.replace("STRUCT_NR_PAGES", "")
        text = text.replace("STORE_NR_PAGES", "")
        text = text.replace("SUBMIT_EVENT", "")

    return text


def attach(bpf, args):
    bpf.attach_kretprobe(
        event="try_to_free_mem_cgroup_pages",
        fn_name="probe_try_to_free_mem_cgroup_pages"
    )


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("namespace", ct.c_ulonglong),
                ("nr_pages", ct.c_ulong),
                ("name", ct.c_char * 16)]


def output(bpf, fmt="plain"):
    if fmt == "plain":
        print()
        for (k, v) in bpf.get_table('reclaim').items():
            name = k.name.decode("ascii")
            if not name.startswith("postgres"):
                return

            size = utils.size(v.value * PAGE_SIZE)
            print("[{}] {}: {}".format(k.pid, k.name, size))

    bpf.get_table('reclaim').clear()


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=pre_process(text, args), debug=debug)
    attach(bpf, args)
    exiting = False

    def print_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        name = event.name.decode("ascii")
        if not name.startswith("postgres"):
            return
        print("Event: pid {} name {} namespace {} reclaimed pages {}".format(
            event.pid, name, event.namespace, event.nr_pages))

    if args.debug:
        bpf["events"].open_perf_buffer(print_event)

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
        description="Track memory page reclaim by postgres processes",
        formatter_class=argparse.RawDescriptionHelpFormatter)
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
