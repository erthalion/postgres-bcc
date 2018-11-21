#!/usr/bin/python
#
# query_cache.py Summarize cache references and cache misses by postgres backend.
#                Cache reference and cache miss are corresponding events defined in
#                uapi/linux/perf_event.h, it varies to different architecture.
#                On x86-64, they mean LLC references and LLC misses. Postgres
#                backend provides a query string. Based on llstat.py from bcc.
#
#                For Linux, uses BCC, eBPF.
#
# SEE ALSO: perf top -e cache-misses -e cache-references -a -ns pid,cpu,comm
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# Copyright (c) 2016 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2016   Teng Qin   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

parser = argparse.ArgumentParser(
    description="Summarize cache references and misses by postgres backend",
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

def get_pid_cmdline(pid):
    try:
        return open("/proc/{}/cmdline".format(pid)).read().strip()
    except FileNotFoundError as ex:
        return "postgres: backend {}".format(pid)

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

struct key_t {
    int pid;
    char name[TASK_COMM_LEN];
};

BPF_HASH(send, struct key_t);
BPF_HASH(recv, struct key_t);

int on_recv(struct pt_regs *ctx) {
    struct key_t key = {};
    key.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key.name), sizeof(key.name));

    u64 zero = 0, *val;
    val = recv.lookup_or_init(&key, &zero);
    (*val) += PT_REGS_PARM3(ctx);

    return 0;
}

int on_send(struct pt_regs *ctx) {
    struct key_t key = {};
    key.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key.name), sizeof(key.name));

    u64 zero = 0, *val;
    val = send.lookup_or_init(&key, &zero);
    (*val) += PT_REGS_PARM3(ctx);

    return 0;
}
"""

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text, debug=4)
b.attach_kprobe(event="sys_sendto", fn_name="on_send")
b.attach_kprobe(event="sys_send", fn_name="on_send")
b.attach_kprobe(event="sys_recvfrom", fn_name="on_recv")
b.attach_kprobe(event="sys_recv", fn_name="on_recv")

print("Running for {} seconds or hit Ctrl-C to end.".format(args.duration))

try:
    sleep(float(args.duration))
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, lambda signal, frame: print())

print("Send")
for (k, v) in b.get_table('send').items():
    if k.name == b"postgres":
        print("{} {}: {}".format(k.pid, get_pid_cmdline(k.pid), size(v.value)))

print()

print("Receive")
for (k, v) in b.get_table('recv').items():
    if k.name == b"postgres":
        print("{} {}: {}".format(k.pid, get_pid_cmdline(k.pid), size(v.value)))
