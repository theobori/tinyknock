#include <stdlib.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/in.h>

#include "./rule.h"

int rule_xfsm_fill_bpf_map(int map_fd, configuration_t *config)
{
    xfsm_key_t k;
    xfsm_value_t v;

    k = (xfsm_key_t) {0, IPPROTO_TCP, 0, 1000};
    v.next_action = XDP_DROP;
    v = (xfsm_value_t) { XDP_DROP, 0, 0};
    bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);

    k = (xfsm_key_t) {1, IPPROTO_UDP, 1000, 2000};
    v = (xfsm_value_t) { XDP_DROP, 0, 0};

    bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);

    k = (xfsm_key_t) {2, IPPROTO_TCP, 2000, 3000};
    v = (xfsm_value_t) { XDP_PASS, 1, 8000};

    bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);

    k = (xfsm_key_t) {0, IPPROTO_TCP, 0, 3000};
    v = (xfsm_value_t) { XDP_DROP, 0, 0};
    bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);

    k = (xfsm_key_t) {1, IPPROTO_TCP, 3000, 2000};
    v = (xfsm_value_t) { XDP_DROP, 0, 0};

    bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);

    k = (xfsm_key_t) {2, IPPROTO_TCP, 2000, 1000};
    v = (xfsm_value_t) { XDP_DROP, 1, 8000};

    bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);

    return EXIT_SUCCESS;
}
