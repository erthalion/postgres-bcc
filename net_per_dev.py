#!/usr/bin/env python
#
# net_per_dev   Track how much data was transmitted per netword device
#
# usage: net_per_dev [-d]


from __future__ import print_function
from time import sleep

import argparse
import ctypes as ct
import signal

from bcc import BPF

import utils


bpf_text = """
#include <linux/ptrace.h>

struct key_t {
    char device[10];
};

struct net_data {
    u32 pid;
    u32 __padding;
    unsigned int len;
    char device[10];
};

#define    IFNAMSIZ    16

struct net_device {
    char name[10];
};

struct sk_buff {
    union {
        struct {
            /* These two members must be first. */
            struct sk_buff        *next;
            struct sk_buff        *prev;

            union {
                struct net_device    *dev;
                /* Some protocols might use this space to store information,
                 * while device pointer would be NULL.
                 * UDP receive path is one user.
                 */
                unsigned long        dev_scratch;
            };
        };
        struct rb_node   rbnode; /* used in netem, ip4 defrag, and tcp stack */
        struct list_head list;
    };

    union {
        struct sock        *sk;
        int            ip_defrag_offset;
    };

    union {
        ktime_t        tstamp;
        u64        skb_mstamp_ns; /* earliest departure time */
    };
    /*
     * This is the control buffer. It is free to use for every
     * layer. Please put your private variables there. If you
     * want to keep them across layers you have to do a skb_clone()
     * first. This is owned by whoever has the skb queued ATM.
     */
    char            cb[48] __aligned(8);

    union {
        struct {
            unsigned long    _skb_refdst;
            void        (*destructor)(struct sk_buff *skb);
        };
        struct list_head    tcp_tsorted_anchor;
    };

    struct    sec_path    *sp;
    unsigned long         _nfct;
    struct nf_bridge_info    *nf_bridge;
    unsigned int        len,
                data_len;
    __u16            mac_len,
                hdr_len;
};

BPF_PERF_OUTPUT(events);

BPF_HASH(net_data_hash, struct key_t);

int probe_dev_hard_start_xmit(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct sk_buff buff = {};
    struct net_device device = {};
    struct key_t key = {};
    bpf_probe_read(&buff,
                    sizeof(buff),
                    ((struct sk_buff *)PT_REGS_PARM1(ctx)));

    bpf_probe_read(&device,
                    sizeof(device),
                    ((struct net_device *)PT_REGS_PARM2(ctx)));

    struct net_data data = {};
    data.pid = pid;
    data.len = buff.len;
    bpf_probe_read(&data.device,
                    IFNAMSIZ,
                    device.name);
    bpf_probe_read(&key.device,
                    IFNAMSIZ,
                    device.name);

    u64 zero = 0, *val;
    val = net_data_hash.lookup_or_init(&key, &zero);
    (*val) += buff.len;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


def attach(bpf):
    bpf.attach_kprobe(
        event="dev_hard_start_xmit",
        fn_name="probe_dev_hard_start_xmit")


# signal handler
def signal_ignore(sig, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulong),
                ("len", ct.c_uint),
                ("device", ct.c_char * 10)]


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("Event: pid {} device {} len {}".format(
        event.pid, event.device, event.len))


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=bpf_text, debug=debug)
    attach(bpf)
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

    print("Total")
    for (k, v) in bpf.get_table("net_data_hash").items():
        print('{}: {}'.format(k.device.decode("ascii"), utils.size(v.value)))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Track how much data was transmitted per netword device",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "-d", "--debug", action='store_true', default=False,
        help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
