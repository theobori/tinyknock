#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <asm-generic/errno-base.h>

#include "event/sequence_event.h"
#include "./rule/rule.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1);
} sequence_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, sequence_key_t);
	__type(value, sequence_value_t);
	__uint(max_entries, 32);
} sequence SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, xfsm_key_t);
	__type(value, xfsm_value_t);
	__uint(max_entries, 256);
} xfsm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, target_key_t);
	__type(value, target_value_t);
	__uint(max_entries, 32);
} target SEC(".maps");

/**
 * @brief Parse Ethernet header
 * 
 * @param cursor 
 * @param ethhdr 
 * @param data_end 
 * @return int 
 */
static __always_inline int parse_ethhdr(void **cursor, struct ethhdr **ethhdr,
    void *data_end)
{
	struct ethhdr *eth = *cursor;
	int hdrsize = sizeof(*eth);

	if (*cursor + hdrsize > data_end)
		return -1;

	*cursor += hdrsize;
	*ethhdr = eth;

	return bpf_htons(eth->h_proto);
}

/**
 * @brief Parse IP header
 * 
 * @param cursor 
 * @param ip 
 * @param data_end 
 * @return int 
 */
static __always_inline int parse_iphdr(void **cursor, struct iphdr **ip,
    void *data_end)
{
    *ip = *cursor;
    *cursor += sizeof(struct iphdr);

    return *cursor > data_end;
}

/**
 * @brief Parse UDP/TCP header.
 * 
 *  This function is also used for TCP because the `dest` field is
 * at the same location.
 * 
 * @param cursor 
 * @param udp 
 * @param data_end 
 * @return int 
 */
static __always_inline int parse_udphdr(void **cursor, struct udphdr **udp,
    void *data_end)
{
    *udp = *cursor;
    *cursor += sizeof(struct udphdr);

    return *cursor > data_end;
}

/**
 * @brief Check if the `port` if allowed from a specific `addr`
 * 
 * @param addr 
 * @param port 
 * @param protocol 
 * @return enum xdp_action
 */
static __always_inline enum xdp_action target_port_xdp_action(__u32 addr,
__u16 port, __u8 protocol)
{
    target_key_t tk = { addr, port };
    void *lookup = bpf_map_lookup_elem(&target, &tk);

    if (!lookup)
        return XDP_DROP;

    return ((target_value_t *) lookup)->action;
}

/**
 * @brief Submit event to the ring buffer
 * 
 * @param port 
 * @param xv 
 * @param step 
 * @param protocol 
 * @return void 
 */
static __always_inline void sequence_rb_submit(__u16 port,
    xfsm_value_t *xv, __u8 step, __u8 protocol)
{
    sequence_event_t *event = bpf_ringbuf_reserve(&sequence_rb,
        sizeof(*event), 0);

    if (!event)
        return;

    event->port = port;
    event->step = step;
    event->is_target = xv->is_next_target;
    event->next_port = xv->next_port;
    event->protocol = protocol;

    bpf_ringbuf_submit(event, 0);
}

/**
 * @brief Check for `addr` sequence
 * 
 * @param addr 
 * @param port 
 * @param protocol 
 * @return void 
 */
static __always_inline void sequence_xdp_action(__u32 addr, __u16 port,
    __u8 protocol)
{
    void *lookup;
    xfsm_value_t *xv;

    sequence_key_t sk = { addr };
    sequence_value_t sv = {0};

    lookup = bpf_map_lookup_elem(&sequence, &sk);
    if (lookup) {
        sv.step = ((sequence_value_t *) lookup)->step;
        sv.last_port = ((sequence_value_t *) lookup)->last_port;
    }
    
    xfsm_key_t xk = { sv.step, protocol, sv.last_port, port};

    lookup = bpf_map_lookup_elem(&xfsm, &xk);
    if (!lookup) {
        bpf_map_delete_elem(&sequence, &sk);

        return;
    }

    xv = (xfsm_value_t *) lookup;

    if (xv->is_next_target) {
        target_key_t tk = { addr, xv->next_port };
        target_value_t tv = { xv->next_action };

        bpf_map_update_elem(&target, &tk, &tv, BPF_ANY);
    }

    sv.step += 1;
    sv.last_port = port;

    bpf_map_update_elem(&sequence, &sk, &sv, BPF_ANY);

    sequence_rb_submit(port, xv, sv.step, protocol);
}

/**
 * @brief Filter the `addr` with `port`
 * 
 * @param addr 
 * @param port 
 * @param protocol 
 * @return enum xdp_action
 */
static __always_inline enum xdp_action filter_xdp_action(__u32 addr,
    __u16 port, __u8 protocol)
{
    sequence_xdp_action(addr, port, protocol);

    return target_port_xdp_action(addr, port, protocol);
}

/**
 * @brief Filter the `addr` with `port` for the UDP protocol
 * 
 * @param cursor 
 * @param ip 
 * @param data_end 
 * @return __always_inline enum 
 */
static __always_inline enum xdp_action filter_udp_xdp_action(void **cursor,
    struct iphdr *ip, void *data_end)
{
    struct udphdr *udp;
    
    int err = parse_udphdr(cursor, &udp, data_end);
    if (err)
        return XDP_DROP;

    return filter_xdp_action(bpf_ntohl(ip->saddr), bpf_htons(udp->dest),
        ip->protocol);
}

SEC("xdp")
/**
 * @brief XDP program
 * 
 * @param ctx 
 * @return enum xdp_action 
 */
enum xdp_action xdp_port_knock(struct xdp_md *ctx)
{
    int err, p;

    void *data = (void *)(long) ctx->data;
    void *data_end = (void *)(long) ctx->data_end;
    void *cursor = data;

    struct ethhdr *eth;

    p = parse_ethhdr(&cursor, &eth, data_end);
    
    if (p == -1)
        return XDP_DROP;
    if (p != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip;
    err = parse_iphdr(&cursor, &ip, data_end);
    if (err) {
        return XDP_DROP;
    }

    switch (ip->protocol)
    {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        return filter_udp_xdp_action(&cursor, ip, data_end);
    default:
        break;
    }

    return XDP_PASS;
}
