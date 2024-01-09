#ifndef __SEQUENCE_EVENT_H__
#define __SEQUENCE_EVENT_H__

#include <asm-generic/int-ll64.h>

/**
 * @brief Sequence event used with the ring buffer
 * 
 */
typedef struct sequence_event_s {
    __u8 step;
    __u16 port;
    __u16 next_port;
    __u8 is_target;
    __u8 protocol;
} sequence_event_t;

#endif
