#!/usr/bin/env python
#

from __future__ import print_function
from time import sleep
from bcc import BPF

import argparse
import ctypes as ct
import signal
import sys

import utils


text = """
#include <linux/ptrace.h>
#include <linux/file.h>

#define HASH_SIZE 2^14

struct key_t {
    int pid;
    size_t size;
    int flags;
    char name[TASK_COMM_LEN];
};

struct truncate_key_t {
    int fd;
    char file[100];
    char name[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(mmap_size, struct key_t, long);
BPF_HASH(anon_shm_size, struct key_t, long);
BPF_HASH(shm_size, struct truncate_key_t, long);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

static inline __attribute__((always_inline)) void get_truncate_key(struct truncate_key_t* key) {
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int probe_pg_shared_memory_create(struct pt_regs *ctx, size_t size, bool makePrivate, int port, void **shim)
{
    struct key_t key = {};

    get_key(&key);

    unsigned long zero = 0, *val;
    val = mmap_size.lookup_or_init(&key, &zero);
    (*val) += size;

    key.size = size;
    events.perf_submit(ctx, &key, sizeof(key));

    return 0;
}

int syscall__mmap(struct pt_regs *ctx, u64 addr, size_t size, int prot, int flags, int fd, off_t offset)
{
    struct key_t key = {};

    get_key(&key);

    unsigned long zero = 0, *val;
    val = mmap_size.lookup_or_init(&key, &zero);
    (*val) += size;

    key.size = size;
    key.flags = flags;
    events.perf_submit(ctx, &key, sizeof(key));

    return 0;
}

int syscall__shm(struct pt_regs *ctx, u64 sys_key, size_t size, int flags)
{
    struct key_t key = {};

    if (!(flags & IPC_CREAT))
        return 1;

    get_key(&key);

    unsigned long zero = 0, *val;
    val = anon_shm_size.lookup_or_init(&key, &zero);
    (*val) += size;

    key.size = size;
    key.flags = flags;
    events.perf_submit(ctx, &key, sizeof(key));

    return 0;
}

int probe_do_truncate(struct pt_regs *ctx, struct dentry *dentry, int size, unsigned int time_attrs, struct file *filep)
{
    struct truncate_key_t key = {};

    get_truncate_key(&key);
    bpf_probe_read(&key.file, sizeof(key.file), (void *)dentry->d_name.name);

    unsigned long zero = 0, *val;
    val = shm_size.lookup_or_init(&key, &zero);
    (*val) = size;

    // key.fd = fd;
    // events.perf_submit(ctx, &key, sizeof(key));

    return 0;
}
"""


def attach(bpf, args):
    binary_path = args.path
    pid = args.pid

    # bpf.attach_uprobe(
        # name=binary_path,
        # sym="dsm_create",
        # fn_name="probe_dsm_create",
        # pid=pid)
    bpf.attach_uprobe(
        name=binary_path,
        sym="PGSharedMemoryCreate",
        fn_name="probe_pg_shared_memory_create",
        pid=pid)

    # bpf.attach_kprobe(
        # event=bpf.get_syscall_fnname("mmap"),
        # fn_name="syscall__mmap"
    # )

    bpf.attach_kprobe(
        event=bpf.get_syscall_fnname("shmget"),
        fn_name="syscall__shm"
    )

    bpf.attach_kprobe(
        event="do_truncate",
        fn_name="probe_do_truncate"
    )


# signal handler
def signal_ignore(signal, frame):
    print()


# class Data(ct.Structure):
    # _fields_ = [("pid", ct.c_int), ("name", ct.c_char * 16)]


class DataDebug(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("size", ct.c_ulong),
                ("flags", ct.c_int),
                ("name", ct.c_char * 16)]


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=text, debug=debug)
    attach(bpf, args)
    exiting = False

    def print_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(DataDebug)).contents
        name = event.name.decode("ascii")
        if not name.startswith("postgres"):
            return
        print("Event: pid {} name {} size {} flags {}".format(
            event.pid, event.name, event.size, bin(event.flags)))

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
            print("Detaching...")
            break

    print()
    print("mmap:")
    for (k, v) in bpf.get_table('mmap_size').items():
        size = utils.size(v.value)
        print("[{}] {}: {}".format(k.pid, k.name.decode("ascii"), size))

    print("anon shm:")
    for (k, v) in bpf.get_table('anon_shm_size').items():
        size = utils.size(v.value)
        print("[{}] {}: {}".format(k.pid, k.name.decode("ascii"), size))

    print("shm:")
    for (k, v) in bpf.get_table('shm_size').items():
        size = utils.size(v.value)
        print("[{}]: {}".format(k.file.decode("ascii"), size))


def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to target binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
