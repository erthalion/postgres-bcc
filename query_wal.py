#!/usr/bin/python
#

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

parser = argparse.ArgumentParser(
    description="",
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

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
b.attach_uprobe(
    name=args.postgres_path,
    sym="exec_simple_query",
    fn_name="probe_exec_simple_query")
b.attach_uretprobe(
    name=args.postgres_path,
    sym="exec_simple_query",
    fn_name="probe_exec_simple_query_finish")
b.attach_uprobe(
    name=args.postgres_path,
    sym="XLogInsertRecord",
    fn_name="probe_wal_insert_record")

print("Running for {} seconds or hit Ctrl-C to end.".format(args.duration))

try:
    sleep(float(args.duration))
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, lambda signal, frame: print())

print("Detaching...")
print()

for (k, v) in b.get_table('wal_records').items():
    print("[{}] {}: {}".format(k.pid, k.query, v.value))
