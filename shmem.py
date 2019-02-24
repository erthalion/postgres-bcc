#!/usr/bin/env python
#
# shmem     Track shared memory allocation by postgres.
#
# usage: shmem $PG_BIN/postgres [-d] [-c CONTAINER_ID] [-n NAMESPACE]
#                               [-i INTERVAL]


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
    STRUCT_SIZE
    STRUCT_FLAGS
    u64 namespace;
    char name[TASK_COMM_LEN];
};

struct truncate_key_t {
    u64 namespace;
    char file[100];
    char name[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(mmap_size, struct key_t, long);
BPF_HASH(anon_shm_size, struct key_t, long);
BPF_HASH(shm_size, struct truncate_key_t, long);

static inline __attribute__((always_inline))
void get_key(struct key_t* key)
{
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

static inline __attribute__((always_inline))
void get_truncate_key(struct truncate_key_t* key)
{
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int probe_pg_shared_memory_create(struct pt_regs *ctx, size_t size,
                                  bool makePrivate, int port, void **shim)
{
    struct key_t key = {};

    get_key(&key);

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    unsigned long zero = 0, *val;
    val = mmap_size.lookup_or_init(&key, &zero);
    (*val) += size;

    STORE_SIZE
    SUBMIT_EVENT

    return 0;
}

int syscall__shm(struct pt_regs *ctx, u64 sys_key, size_t size, int flags)
{
    struct key_t key = {};

    if (!(flags & IPC_CREAT))
        return 1;

    get_key(&key);

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    unsigned long zero = 0, *val;
    val = anon_shm_size.lookup_or_init(&key, &zero);
    (*val) += size;

    STORE_SIZE
    STORE_FLAGS
    SUBMIT_EVENT

    return 0;
}

int probe_do_truncate(struct pt_regs *ctx, struct dentry *dentry, int size,
                      unsigned int time_attrs, struct file *filep)
{
    struct truncate_key_t key = {};

    get_truncate_key(&key);

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    bpf_probe_read(&key.file, sizeof(key.file), (void *)dentry->d_name.name);

    unsigned long zero = 0, *val;
    val = shm_size.lookup_or_init(&key, &zero);
    (*val) = size;

    return 0;
}
"""


def attach(bpf, args):
    binary_path = args.path
    pid = args.pid

    bpf.attach_uprobe(
        name=binary_path,
        sym="PGSharedMemoryCreate",
        fn_name="probe_pg_shared_memory_create",
        pid=pid)

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


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("size", ct.c_ulong),
                ("flags", ct.c_int),
                ("namespace", ct.c_ulonglong),
                ("name", ct.c_char * 16)]


def pre_process(text, args):
    text = utils.replace_namespace(text, args)
    if args.debug:
        text = text.replace("STRUCT_SIZE", "size_t size;")
        text = text.replace("STRUCT_FLAGS", "int flags;")
        text = text.replace("STORE_SIZE", "key.size = size;")
        text = text.replace("STORE_FLAGS", "key.flags = flags;")
        text = text.replace(
            "SUBMIT_EVENT",
            "events.perf_submit(ctx, &key, sizeof(key));"
        )
    else:
        text = text.replace("STRUCT_SIZE", "")
        text = text.replace("STRUCT_FLAGS", "")
        text = text.replace("STORE_SIZE", "")
        text = text.replace("STORE_FLAGS", "")
        text = text.replace("SUBMIT_EVENT", "")

    return text


def output(bpf, fmt="plain"):
    if fmt == "plain":
        print()
        print("mmap:")
        for (k, v) in bpf.get_table('mmap_size').items():
            size = utils.size(v.value)
            name = k.name.decode("ascii")
            if not name.startswith("postgres"):
                return
            print("[{}]: {}".format(k.pid, size))

        print("anon shm:")
        for (k, v) in bpf.get_table('anon_shm_size').items():
            size = utils.size(v.value)
            name = k.name.decode("ascii")
            if not name.startswith("postgres"):
                return
            print("[{}]: {}".format(k.pid, size))

        print("shm:")
        for (k, v) in bpf.get_table('shm_size').items():
            size = utils.size(v.value)
            name = k.name.decode("ascii")
            if not name.startswith("postgres"):
                return
            print("[{}]: {}".format(k.file.decode("ascii"), size))

    bpf.get_table('mmap_size').clear()
    bpf.get_table('shm_size').clear()
    bpf.get_table('anon_shm_size').clear()


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=pre_process(text, args), debug=debug)
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
            sleep(args.interval)
            output(bpf)

            if args.debug:
                bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        if exiting:
            print("Detaching...")
            break

    output(bpf)


def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to target binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
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
