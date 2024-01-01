#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno-base.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct syscalls_enter_open_at_args {
	u64 unused;

	u32 syscall_nr;
	u64 dfd;
	u64 filename_ptr;
	u64 flags;
	u64 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct syscalls_enter_open_at_args *ctx)
{
	return 0;
}