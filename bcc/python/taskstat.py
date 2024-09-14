from bcc import BPF
from time import sleep
from collections import defaultdict
import argparse

parser = argparse.ArgumentParser(
    description="Summarize task time in differenct stats. Please `echo 1 > /procs/sys/kernel/sched_schedstat` first",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("-L", "--tids", action="store_true", default=False,
    help="print a summary per thread ID")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)

bpf_text = """
#include <linux/sched.h>

struct taskstat {
    u64 runtime;
    u64 wait;
    u64 blocked;
    u64 iowait;
    u32 tgid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(data, u32, struct taskstat);

RAW_TRACEPOINT_PROBE(sched_stat_runtime) {
    // TP_PROTO(struct task_struct *tsk, u64 runtime, u64 vruntime)
    struct task_struct *p = (void *)ctx->args[0];
    u32 pid = p->pid;
    u64 delay = (u64)ctx->args[1];
    struct taskstat zero = {0}, *val;
    val = data.lookup_or_try_init(&pid, &zero);
    if (val) {
        val->runtime += delay;
        if (val->comm[0] == 0) {
            val->tgid = p->tgid;
            bpf_probe_read_kernel_str(&val->comm, sizeof(val->comm), p->comm);
        }
    }
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_stat_wait) {
    // TP_PROTO(struct task_struct *tsk, u64 delay)
    struct task_struct *p = (void *)ctx->args[0];
    u32 pid = p->pid;
    u64 delay = (u64)ctx->args[1];
    struct taskstat zero = {0}, *val;
    val = data.lookup_or_try_init(&pid, &zero);
    if (val) {
        val->wait += delay;
        if (val->comm[0] == 0) {
            val->tgid = p->tgid;
            bpf_probe_read_kernel_str(&val->comm, sizeof(val->comm), p->comm);
        }
    }
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_stat_blocked) {
    // TP_PROTO(struct task_struct *tsk, u64 delay)
    struct task_struct *p = (void *)ctx->args[0];
    u32 pid = p->pid;
    u64 delay = (u64)ctx->args[1];
    struct taskstat zero = {0}, *val;
    val = data.lookup_or_try_init(&pid, &zero);
    if (val) {
        val->blocked += delay;
        if (val->comm[0] == 0) {
            val->tgid = p->tgid;
            bpf_probe_read_kernel_str(&val->comm, sizeof(val->comm), p->comm);
        }
    }
    return 0;
}

RAW_TRACEPOINT_PROBE(sched_stat_iowait) {
    // TP_PROTO(struct task_struct *tsk, u64 delay)
    struct task_struct *p = (void *)ctx->args[0];
    u32 pid = p->pid;
    u64 delay = (u64)ctx->args[1];
    struct taskstat zero = {0}, *val;
    val = data.lookup_or_try_init(&pid, &zero);
    if (val) {
        val->iowait += delay;
        if (val->comm[0] == 0) {
            val->tgid = p->tgid;
            bpf_probe_read_kernel_str(&val->comm, sizeof(val->comm), p->comm);
        }
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
print("Tracing Task time in Differenct States... Hit Ctrl-C to end.")


def time_unit(nsec):
    return int(nsec / 1000)


def proc_comm(tgid):
    try:
        comm = open("/proc/%d/cmdline" % tgid, "r").read()
        return comm.split('\0')[0]
    except IOError:
        return ""


data = b.get_table("data")
exiting = 0
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1
        print()

    if not args.tids:
        print("{:<8} {:<16} {:<16} {:<16} {:<16} {}".format("PID", "RUNNING", "RUNNABLE", "BLOCKED", "IOWAITING", "COMMAND"))
        tgids = {}
        tgids_comm = {}
        for key, value in data.items():
            tid = key.value
            tgid = value.tgid
            if tgid not in tgids:
                tgids[tgid] = [] 
            tgids[tgid].append(value)
            if tgid == tid:
                 tgids_comm[tgid] = value.comm

        def tgid_to_comm(tgid):
            comm = proc_comm(tgid)
            if comm != "":
                return comm
            elif tgid in tgids_comm:
                return tgids_comm[tgid].decode('utf-8')
            else:
                return ""

        for tgid, values in sorted(tgids.items(), key=lambda item: item[0]):
            runtime = sum([v.runtime for v in values])
            wait = sum([v.wait for v in values])
            blocked = sum([v.blocked for v in values])
            iowait = sum([v.iowait for v in values])
            print("{:<8} {:<16} {:<16} {:<16} {:<16} {}".format(tgid, time_unit(runtime), time_unit(wait), time_unit(blocked), time_unit(iowait), tgid_to_comm(tgid)))
    else:
        print("{:<8} {:<8} {:<16} {:<16} {:<16} {:<16} {:<20} {}".format("PID", "TID", "RUNNING", "RUNNABLE", "BLOCKED", "IOWAITING", "THREAD", "PROCESS"))
        for key, value in sorted(data.items(), key=lambda item: item[1].tgid):
            tid = key.value
            tgid = value.tgid

            print("{:<8} {:<8} {:<16} {:<16} {:<16} {:<16} {:<20} {}".format(value.tgid, tid, 
                    time_unit(value.runtime), time_unit(value.wait), time_unit(value.blocked), time_unit(value.iowait), value.comm.decode('utf-8')[:20], proc_comm(tgid)))

    data.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()