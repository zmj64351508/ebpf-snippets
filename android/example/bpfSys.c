#include <stdint.h>
#include <bpf_helpers.h>

DEFINE_BPF_MAP_GRW(sys_enter_map, HASH, uint32_t, uint64_t, 1024, AID_SYSTEM);

struct syscalls_enter_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

DEFINE_BPF_PROG("tracepoint/raw_syscalls/sys_enter", AID_ROOT, AID_SYSTEM, tp_sys_enter)
(struct syscalls_enter_args *args)
{
    uint32_t key = bpf_get_current_pid_tgid();
    uint64_t one = 1;

    uint64_t *cnt = bpf_sys_enter_map_lookup_elem(&key);
    if (cnt) {
        *cnt = *cnt + 1;
    } else {
        bpf_sys_enter_map_update_elem(&key, &one, BPF_NOEXIST);
    }
    return 0;
}

LICENSE("GPL");
