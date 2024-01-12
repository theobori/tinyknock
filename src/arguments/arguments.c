#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../argparse/argparse.h"
#include "./arguments.h"

/**
 * @brief CLI usage
 * 
 */
static const char *const usages[] = {
    "tinyknock [options]",
    NULL,
};

void arguments_parse(arguments_t *arguments, int argc, const char *argv[])
{
    struct argparse argparse;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Required options"),
        OPT_STRING('f', "file", &arguments->file, "Filters YAML file path", NULL, 0, 0),
        OPT_STRING('i', "ifname", &arguments->ifname, "Network interface name", NULL, 0, 0),
        OPT_STRING('b', "bpf-file", &arguments->bpf_object_file, "BPF object file path", NULL, 0, 0),
        OPT_INTEGER('d', "detach", &arguments->xdp_prog_id, "Detach an XDP program from a network interface (with its ID)", NULL, 0, 0),
        OPT_INTEGER('m', "xdp-mode", &arguments->xdp_mode, "XDP mode (by default 2)", NULL, 0, 0),
        OPT_END(),
    };

    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, DESCRIPTION, "\nXDP modes:\n"
        "    1 -> XDP_MODE_NATIVE\n"
        "    2 -> XDP_MODE_SKB\n"
        "    3 -> XDP_MODE_HW\n");
    argparse_parse(&argparse, argc, argv);
}

arguments_t arguments_create_and_parse(int argc, const char *argv[]) {
    arguments_t arguments = {0};

    arguments_parse(&arguments, argc, argv);

    return arguments;
}

bool arguments_check(arguments_t *arguments) {
    return arguments->ifname &&
        arguments->xdp_mode > 0 &&
        arguments->xdp_mode < 4;
}
