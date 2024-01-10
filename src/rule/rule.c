#include <stdlib.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/in.h>

#include "./rule.h"

#define POLICY_COUNT_MIN 1
#define SEQUENCE_COUNT_MIN 2
#define START_PORT 0

/**
 * @brief Process a single policy
 * 
 * @param map_fd 
 * @param policy 
 * @return int 
 */
static int policy_process(int map_fd, policy_t *policy) {
    xfsm_key_t k;
    xfsm_value_t v;
    sequence_t sequence, next_sequence;

    unsigned short last_port = START_PORT;

    if (policy->sequence_count < SEQUENCE_COUNT_MIN)
        return EXIT_FAILURE;
    
    for (unsigned int i = 0; i < policy->sequence_count; i++) {
        sequence = policy->sequence[i];
        next_sequence = policy->sequence[i + 1];

        k.step = i;
        k.protocol = sequence.protocol;
        k.last_port = last_port;
        k.port = sequence.value;

        if (i == policy->sequence_count - 1) {
            v.is_next_target = 1;
            v.next_action = policy->action;
            v.next_port = policy->target;
        } else {
            v.is_next_target = 0;
            v.next_port = next_sequence.value;
            v.next_action = 0;
        }

        last_port = sequence.value;

        bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);
    }

    bpf_map_update_elem(map_fd, &k, &v, BPF_NOEXIST);

    return EXIT_SUCCESS;
}

int rule_xfsm_fill_bpf_map(int map_fd, configuration_t *config)
{
    int err;
    policy_t policy;

    if (config->policies_count < POLICY_COUNT_MIN)
        return EXIT_FAILURE;

    for (unsigned int i = 0; i < config->policies_count; i++) {
        policy = config->policies[i];

        err = policy_process(map_fd, &policy);
        if (err)
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
