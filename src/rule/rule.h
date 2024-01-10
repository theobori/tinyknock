#ifndef __RULE_H__
#define __RULE_H__

#include <asm-generic/int-ll64.h>

#include "../configuration/configuration.h"

/**
 * @brief Sequence table key
 * 
 */
typedef struct sequence_key_s {
    __u32 addr;
} sequence_key_t;
/**
 * @brief Sequence table value
 * 
 */
typedef struct sequence_value_s {
    __u8 step;
    __u16 last_port;
    __u8 unused;
} sequence_value_t;
/**
 * @brief XFSML table key
 * 
 */
typedef struct xfsm_key_s {
    __u8 step;
    __u8 protocol;
    __u16 last_port;
    __u16 port;
    __u16 unused;
} xfsm_key_t;
/**
 * @brief XFSM table value
 * 
 */
typedef struct xfsm_value_s {
    __u8 next_action;
    __u8 is_next_target;
    __u16 next_port;
} xfsm_value_t;

/**
 * @brief Target key
 * 
 */
typedef struct target_key_s {
    __u32 addr;
    __u16 port;
    __u16 unused;
} target_key_t;

/**
 * @brief Target value
 * 
 */
typedef struct target_value_s {
    __u8 action;
    const __u8 unused[3];
} target_value_t;

/**
 * @brief Fill the XFSM BPF map from the configuration
 * 
 */
int rule_xfsm_fill_bpf_map(int map_fd, configuration_t *config);

#endif
