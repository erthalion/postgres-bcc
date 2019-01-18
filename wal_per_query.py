#!/usr/bin/python
#
# wal_per_query.py  Summarize WAL writes by postgres backend.
#                   For Linux, uses BCC, eBPF.
#                   To trace only inside a particular container, you can use
#                   --container option (that will assume docker), you need to
#                   provide a namespace identificator. In case of docker container
#                   to get one you can first check out container Pid:
#
#                      docker inspect postgres_test --format='{{.State.Pid}}'
#
#                   Then use lsns to get a namespace id
#
#                      lsns -p $PID -t pid
#
# usage: wal_per_query $PG_BIN/postgres [-d] [-p PID] [-n NAMESPACE]


from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

import utils


# load BPF program
bpf_text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#define HASH_SIZE 2^14
#define QUERY_LEN 100
#define STACK_STORAGE_SIZE 1024

typedef unsigned int uint32;
typedef unsigned long int uint64;
typedef unsigned char uint8;
typedef uint32 TransactionId;
typedef uint8 RmgrId;
typedef uint32 pg_crc32c;
typedef uint64 XLogRecPtr;

typedef struct XLogRecData
{
    struct XLogRecData *next;    /* next struct in chain, or NULL */
    char               *data;            /* start of rmgr data to include */
    uint32              len;            /* length of rmgr data to include */
} XLogRecData;

typedef struct XLogRecord
{
	uint32		xl_tot_len;		/* total len of entire record */
	TransactionId xl_xid;		/* xact id */
	XLogRecPtr	xl_prev;		/* ptr to previous record in log */
	uint8		xl_info;		/* flag bits, see below */
	RmgrId		xl_rmid;		/* resource manager for this record */
	/* 2 bytes of padding here, initialize to zero */
	pg_crc32c	xl_crc;			/* CRC for this record */

	/* XLogRecordBlockHeaders and XLogRecordDataHeader follow, no padding */

} XLogRecord;

struct key_t {
    int cpu;
    int pid;
    u64 namespace;
    int len;
    char query[QUERY_LEN];
};

struct backend {
    int pid;
    char query[QUERY_LEN];
};

BPF_HASH(wal_records, struct key_t);
BPF_HASH(queries, u32, struct backend, HASH_SIZE);

static inline __attribute__((always_inline)) int get_key(struct key_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    struct backend *data = queries.lookup(&(key->pid));

    if (data != NULL)
    {
        bpf_probe_read(&(key->query), QUERY_LEN, &(data->query));
        return 1;
    }

    return 0;
}

int probe_wal_insert_record(struct pt_regs *ctx) {
    struct key_t key = {};
    int result = get_key(&key);

    SAVE_NAMESPACE

    CHECK_NAMESPACE

    if (result == 0)
        return 0;

    struct XLogRecData rdata = {};
    struct XLogRecord rec = {};
    bpf_probe_read(&rdata, sizeof(rdata),
                   ((struct XLogRecData *)PT_REGS_PARM1(ctx)));
    bpf_probe_read(&rec, sizeof(rec),
                   ((struct XLogRecord *)rdata.data));

    u64 zero = 0, *val;
    val = wal_records.lookup_or_init(&key, &zero);
    (*val) += rec.xl_tot_len;

    return 0;
}

void probe_exec_simple_query(struct pt_regs *ctx, const char *query_string)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct backend data = {};
    data.pid = pid;
    bpf_probe_read(&data.query, QUERY_LEN, &(*query_string));
    queries.update(&pid, &data);
}

void probe_exec_simple_query_finish(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    queries.delete(&pid);
}
"""


# signal handler
def signal_ignore(signal, frame):
    print()


def attach(bpf, args):
    binary_path = args.path
    pid = args.pid

    bpf.attach_uprobe(
        name=binary_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query",
        pid=pid)
    bpf.attach_uretprobe(
        name=binary_path,
        sym="exec_simple_query",
        fn_name="probe_exec_simple_query_finish",
        pid=pid)
    bpf.attach_uprobe(
        name=binary_path,
        sym="XLogInsertRecord",
        fn_name="probe_wal_insert_record",
        pid=pid)


def pre_process(text, args):
    text = utils.replace_namespace(text, args)
    return text


def run(args):
    print("Attaching...")
    debug = 4 if args.debug else 0
    bpf = BPF(text=pre_process(bpf_text, args), debug=debug)
    attach(bpf, args)
    exiting = False

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

    for (k, v) in bpf.get_table('wal_records').items():
        query = k.query.decode("ascii", "ignore")
        print("[{}:{}] {}: {}".format(k.pid, k.namespace, query, v.value))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Summarize cache references and misses by postgres backend",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=str, help="path to PostgreSQL binary")
    parser.add_argument("-p", "--pid", type=int, default=-1,
            help="trace this PID only")
    parser.add_argument("-c", "--container", type=str,
            help="trace this container only")
    parser.add_argument("-n", "--namespace", type=int,
            help="trace this namespace only")
    parser.add_argument("-d", "--debug", action='store_true', default=False,
            help="debug mode")

    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
