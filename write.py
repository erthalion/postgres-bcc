#!/usr/bin/env python
#
# writes_per_type   How much data was written by backend type. For that we
#                   track vfs_write and analyze user space stacktrace that we've
#                   got, to see which type of write is that. Since we rely on
#                   stacktraces, it's possible that some number of writes
#                   will not have a proper user space stacktrace and will
#                   not be recognized (unknown type). Due to this it probably
#                   can't be used to properly measure amount of write IO, but
#                   incredibly useful for investigation purposes, when one
#                   doesn't know all writes that are coming from PostgreSQL.
#
# usage: writes_per_type [-d]


from __future__ import print_function
from time import sleep
from bcc import BPF, USDT

import argparse
import ctypes as ct
import signal
import sys
import errno


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

text = """
#include <linux/ptrace.h>

#define HASH_SIZE 2^14
#define STACK_STORAGE_SIZE 16384

struct key_t {
    int pid;
    int tgid;
    int user_stack_id;
    size_t size;
    char name[TASK_COMM_LEN];
};

BPF_HASH(write_size, struct key_t, size_t);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->pid = bpf_get_current_pid_tgid();
    key->tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int probe_vfs_write(struct pt_regs *ctx)
{
    struct key_t key = {};
    get_key(&key);

    key.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    key.size = (size_t) PT_REGS_PARM3(ctx);

    size_t zero = 0, *val;
    val = write_size.lookup_or_init(&key, &zero);
    (*val) += (size_t) PT_REGS_PARM3(ctx);

    return 0;
}
"""


def attach(bpf, args):
    bpf.attach_kprobe(event="vfs_write", fn_name="probe_vfs_write")


# signal handler
def signal_ignore(signal, frame):
    print()


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("user_stack_id", ct.c_int),
                ("size", ct.c_size_t),
                ("name", ct.c_char * 16)]


def print_kstack(bpf, stack_id, tgid):
    stack = list(bpf.get_table("stack_traces").walk(stack_id))
    for addr in stack:
        print("        ", end="")
        print("%16x " % addr, end="")
        print("%s" % (bpf.ksym(addr)))


def print_stack(bpf, stack_id, tgid):
    stack = list(bpf.get_table("stack_traces").walk(stack_id))
    for addr in stack:
        print("        ", end="")
        print("%16x " % addr, end="")
        print("%s" % (bpf.sym(addr, tgid)))


def event_category(bpf, user_stack_id, tgid):
    process = "unknown"
    action = "unknown"

    if user_stack_id < 0 or user_stack_id in (errno.EFAULT, errno.ENOMEM):
        return (action, process)

    stack = list(bpf.get_table("stack_traces").walk(user_stack_id))
    syms = {bpf.sym(addr, tgid) for addr in stack}

    def contains(*symbols):
        return syms.intersection({s.encode("ascii", "ignore") for s in symbols})

    if contains(
        "XLogFlush",
        "AdvanceXLInsertBuffer",
        "XLogBackgroundFlush",
    ):
        action = "xlog"

    if contains("send_message_to_server_log"):
        action = "log"

    if contains(
        "SlruInternalWritePage",
        "mdextend",
        "mdwrite",
    ):
        action = "heap"

    if contains("latch_sigusr1_handler"):
        action = "latch"

    if contains("exec_simple_query"):
        process = "backend"

    if contains("CheckpointerMain"):
        process = "checkpointer"

    if contains("AutoVacLauncherMain"):
        process = "autovacuum"

    if contains("WalWriterMain"):
        process = "wal_writer"

    if contains("BackgroundWriterMain"):
        process = "background_writer"

    return (action, process)

def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=text, debug=debug)
    attach(bpf, args)
    exiting = False

    def print_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        name = event.name.decode("ascii", "ignore")
        if not name.startswith("postgres"):
            return
        print("Event: pid {} category {} size {}".format(
            event.pid, event_category(bpf, event.user_stack_id, event.pid), event.size))
        print_stack(bpf, event.user_stack_id, event.pid)


    print("Listening...")
    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        if exiting:
            print()
            print("Detaching...")
            print()
            break

    data = {}

    for (k, v) in bpf.get_table('write_size').items():
        if not k.name.decode("ascii", "ignore").startswith("postgres"):
            continue

        action, process = event_category(bpf, k.user_stack_id, k.tgid)
        category = "{},{}".format(process, action)
        data[category] = data.get(category, 0) + v.value

        if args.debug
            print("[{}:{}:{}] {}: {}".format(
                k.name, k.pid, k.user_stack_id,
                event_category(bpf, k.user_stack_id, k.tgid), size(v.value)))
            print_stack(bpf, k.user_stack_id, k.tgid)

    for category, written in data.items():
        print("{}: {}".format(category, size(written)))


def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
