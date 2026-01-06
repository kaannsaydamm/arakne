// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Arakne eBPF Probe ("The Hunter")
// Hooks: sys_execve, sys_mount, sys_ptrace

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct event_t event = {};
    event.pid = pid;
    event.uid = uid;
    
    // Get command name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Get filename argument (1st arg of execve)
    // Note: Reading user space string requires bpf_probe_read_user_str
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), (const char *)ctx->args[0]);

    // Send to userspace (Arakne Go CLI)
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";
