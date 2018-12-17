#!/usr/bin/env python
#
# netdev   Track network devices, that are used to transmit data
#
# usage: netdev [-p PID] [-d]


from __future__ import print_function
from time import sleep
from bcc import BPF, USDT

import argparse
import ctypes as ct
import signal
import sys


text = """
#include <linux/ptrace.h>

struct net_data {
    u32 pid;
    u32 __padding;
    char device[10];
};

#define	IFNAMSIZ	16

struct net_device {
    char            name[10];
};

struct dev_ifalias {
    struct rcu_head rcuhead;
    char ifalias[];
};

BPF_PERF_OUTPUT(events);

void probe_dev_hard_start_xmit(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct net_device device = {};
    bpf_probe_read(&device,
                    sizeof(device),
                    ((struct net_device *)PT_REGS_PARM2(ctx)));

    struct net_data data = {};
    data.pid = pid;
    bpf_probe_read(&data.device,
                    IFNAMSIZ,
                    device.name);
    events.perf_submit(ctx, &data, sizeof(data));
}
"""


def attach(bpf):
    bpf.attach_kprobe(
        event="dev_hard_start_xmit",
        fn_name="probe_dev_hard_start_xmit")


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulong),
                ("device", ct.c_char * 10)]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("Event: pid {} device {}".format(event.pid, event.device))


def run(args):
    print("Attaching...")
    debug = 4
    bpf = BPF(text=text, debug=debug)
    attach(bpf)
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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Track netword devices to transmit data",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
