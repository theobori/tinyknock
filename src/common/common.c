#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <errno.h>
#include <stdio.h>

#include "./common.h"

/**
 * @brief Layer 4 static array to resolve string or value
 * 
 */
static const l4_proto_string_t l4_proto_strings[] = {
    { "tcp", IPPROTO_TCP },
    { "udp", IPPROTO_UDP },
    { "icmp", IPPROTO_ICMP },
};

int l4_proto_resolve(char *name, unsigned char *value,
    enum l4_proto_resolve_choice choice)
{
    l4_proto_string_t entry;
    unsigned int size;

    if (!name && !value)
        return EXIT_FAILURE;

    size = ARRAY_SIZE(l4_proto_strings);

    for (unsigned int i = 0; i < size; i++) {
        entry = l4_proto_strings[i];

        if (choice == VALUE && name && !strcmp(entry.name, name)) {
            *value = entry.value;
            return EXIT_SUCCESS;
        }

        if (choice == NAME && value && *value == entry.value) {
            memcpy(name, entry.name, sizeof(entry.name));
            return EXIT_SUCCESS;
        }
    }

    return EXIT_FAILURE;
}

