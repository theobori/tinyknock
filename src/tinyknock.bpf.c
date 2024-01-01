#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno-base.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_basic(struct xdp_md *ctx)
{
	return XDP_PASS;
}
