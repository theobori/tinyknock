#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>

/**
 * @brief Compute static array length 
 * 
*/
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

/**
 * @brief l4 proto string resolve entry
 * 
 */
typedef struct l4_proto_string_s {
    char name[10];
    unsigned char value;
} l4_proto_string_t;

/**
 * @brief Layer proto resolve choice
 * 
 */
enum l4_proto_resolve_choice {
    NAME = 0,
    VALUE
};

/**
 * @brief Resolve layer 4 name or value
 * 
 * @param name 
 * @param value 
 * @return int 
 */
int l4_proto_resolve(char *name, unsigned char *value,
    enum l4_proto_resolve_choice);

#endif
