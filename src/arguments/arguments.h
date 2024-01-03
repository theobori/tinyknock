#ifndef __ARGUMENTS_H__
#define __ARGUMENTS_H__

#include <stdbool.h>

typedef struct arguments_s {
    char *ifname;
    char *file;
    char *bpf_object_file;
} arguments_t;

void arguments_parse(arguments_t *arguments, int argc, const char *argv[]);
arguments_t arguments_create_and_parse(int argc, const char *argv[]);
bool arguments_check(arguments_t *arguments);

#endif
