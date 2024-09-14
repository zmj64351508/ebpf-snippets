#include <stdio.h>
#include <bpf/BpfMap.h>
#include <libbpf_android.h>

int main()
{
    constexpr const char tp_prog_path[] = "/sys/fs/bpf/prog_bpfSys_tracepoint_raw_syscalls_sys_enter";
    constexpr const char tp_map_path[] = "/sys/fs/bpf/map_bpfSys_sys_enter_map";
    int fd = bpf_obj_get(tp_prog_path);
    int ret = bpf_attach_tracepoint(fd, "raw_syscalls", "sys_enter");
    if (ret < 0) {
	printf("Can't attach raw_syscalls/sys_enter: %d\n", ret);
        return 1;
    }

    typedef android::bpf::BpfMap<uint32_t, uint64_t> SysEnterMap;

    auto map = SysEnterMap(tp_map_path);
    if (!map.isValid()) {
	printf("Can't open file: %s\n", tp_map_path);
        return 1;
    }

    const auto iterFunc = [&](const uint32_t &key, const uint64_t &val, SysEnterMap &map) {
        printf("%u\t%lu\n", key, val);
	map.deleteValue(key);
        return android::base::Result<void>();
    };

    while (1)
    {
        printf("PID\tCOUNT\n");
        map.iterateWithValue(iterFunc);
        printf("\n");
	sleep(2);
    }

    exit(0);
}
