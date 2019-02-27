#!/usr/bin/env python
#
# working_set    Track how frequently data buffers are accessed. This can help
#                estimating how much hot (and less hot) data a database has to
#                calculate values for options like shared_buffers.
#                For now tracking is happening via BufTableLookup, which means
#                we also include prefetch, but do not include local access.
#
# usage: working_set $PG_BIN/postgres [-d] [-p PID] [-i INTERVAL]
#                                     [-c CONTAINER_ID] [-n NAMESPACE]

from __future__ import print_function
from time import sleep

import argparse
import ctypes as ct
import signal

from bcc import BPF

import utils


text = """
#include <linux/ptrace.h>

typedef unsigned int Oid;
typedef unsigned int uint32;

typedef struct RelFileNode
{
	Oid			spcNode;		/* tablespace */
	Oid			dbNode;			/* database */
	Oid			relNode;		/* relation */
} RelFileNode;

typedef enum ForkNumber
{
	InvalidForkNumber = -1,
	MAIN_FORKNUM = 0,
	FSM_FORKNUM,
	VISIBILITYMAP_FORKNUM,
	INIT_FORKNUM

	/*
         * NOTE: if you add a new fork, change MAX_FORKNUM and possibly
         * FORKNAMECHARS below, and update the forkNames array in
         * src/common/relpath.c
         */
} ForkNumber;

typedef uint32 BlockNumber;

typedef struct buftag
{
	RelFileNode rnode;	/* physical relation identifier */
	ForkNumber  forkNum;
	BlockNumber blockNum;	/* blknum relative to begin of reln */
} BufferTag;

struct key_t {
    int spcNode;
    int dbNode;
    int relNode;
    u32 blockNum;
    u64 namespace;
    char name[TASK_COMM_LEN];
};

#define HASH_SIZE 2^14

BPF_PERF_OUTPUT(events);

BPF_HASH(buffers, struct key_t, long);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int probe_buf_table_lookup(struct pt_regs *ctx, BufferTag *buf_tag, uint32 hashcode)
{
    struct key_t key = {};
    get_key(&key);

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    key.spcNode = buf_tag->rnode.spcNode;
    key.dbNode = buf_tag->rnode.dbNode;
    key.relNode = buf_tag->rnode.relNode;
    key.blockNum = buf_tag->blockNum;

    events.perf_submit(ctx, &key, sizeof(key));

    unsigned long zero = 0, *val;
    val = buffers.lookup_or_init(&key, &zero);
    (*val) += 1;

    return 0;
}
"""


# signal handler
def signal_ignore(sig, frame):
    print()


def attach(bpf, args):
    binary_path = args.path
    pid = args.pid

    bpf.attach_uprobe(
        name=binary_path,
        sym="BufTableLookup",
        fn_name="probe_buf_table_lookup",
        pid=pid)


def pre_process(bpf_text, args):
    bpf_text = utils.replace_namespace(bpf_text, args)
    return bpf_text


def output(bpf, fmt="plain"):
    if fmt == "plain":
        print()
        counts = {}

        total = 0

        for (k, v) in bpf.get_table('buffers').items():
            name = k.name.decode("ascii")
            if not name.startswith("postgres"):
                return

            total += v.value
            counts[v.value] = counts.get(v.value, 0) + 1

        if not counts:
            return

        rings = [
            ("0-5",
            utils.size(sum([
                v for k, v in counts.items()
                if 0 < k < 5
            ] * 8192))),
            ("5-50",
            utils.size(sum([
                v for k, v in counts.items()
                if 5 < k < 50
            ] * 8192))),
            ("50-600",
            utils.size(sum([
                v for k, v in counts.items()
                if 50 < k < 600
            ] * 8192))),
            (">600",
            utils.size(sum([
                v for k, v in counts.items()
                if 600 < k
            ] * 8192))),
        ]

    for range_limits, value in rings:
        print("{}:\t{}".format(range_limits, value))

    print("Total access: {}".format(total))
    bpf.get_table('buffers').clear()


class Data(ct.Structure):
    _fields_ = [("spcNode", ct.c_int),
                ("dbNode", ct.c_int),
                ("relNode", ct.c_int),
                ("blockNum", ct.c_int),
                ("namespace", ct.c_ulonglong),
                ("name", ct.c_char * 16)]


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
        print("Event: name {} spcNode {} dbNode {} relNode {} blockNum {}".format(
            name, event.spcNode, event.dbNode, event.relNode, event.blockNum))

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
        description="Summarize cache references & misses by postgres backend",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to PostgreSQL binary")
    parser.add_argument(
        "-p", "--pid", type=int, default=-1,
        help="trace this PID only")
    parser.add_argument(
        "-c", "--container", type=str,
        help="trace this container only")
    parser.add_argument(
        "-n", "--namespace", type=int,
        help="trace this namespace only")
    parser.add_argument(
        "-i", "--interval", type=int, default=5,
        help="after how many seconds output the result")
    parser.add_argument(
        "-d", "--debug", action='store_true', default=False,
        help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
