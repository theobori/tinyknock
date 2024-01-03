#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <xdp/libxdp.h>

#include <cyaml/cyaml.h>

#include "tinyknock.skel.h"
#include "./configuration/configuration.h"
#include "./arguments/arguments.h"

#define ARG_COUNT 2
#define XDP_SECTION_NAME "xdp"

static bool end = false;

static void int_exit(int sig)
{
	end = true;
}

// BPF object
static struct tinyknock_bpf *obj = NULL;
// XDP program
static struct xdp_program *xdp_prog = NULL;

static int tinyknock_init(configuration_t *config, char *filename)
{
	int err;

	// Open and load the BPF program,
    // see bytecode in the skeleton header
	obj = tinyknock_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return EXIT_FAILURE;
	}

    // Attach the BPF program
	err = tinyknock_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		return EXIT_FAILURE;
	}

	// Load the YAML configuration
	err = tinyknock_configuration_init(&config, filename);
	if (err) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int xdp_init(unsigned int ifindex, char *filename) {
	int err;

	// Open the file BPF file object
	xdp_prog = xdp_program__open_file(filename, XDP_SECTION_NAME,
		NULL);

	if (!xdp_prog) {
        printf("Error, load xdp prog failed\n");
        return EXIT_FAILURE;
    }

	// Attach the XDP program
	err = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_SKB, 0);
    if (err) {
        printf("Error, Set xdp fd on %d failed\n", ifindex);
        return EXIT_FAILURE;
    }

	return EXIT_SUCCESS;
}

int main(int argc, const char *argv[])
{
	int err;
	
	unsigned int ifindex = 0;
	configuration_t *config = NULL;
    arguments_t arguments = arguments_create_and_parse(argc, argv);
	
	if (argc < ARG_COUNT || !arguments_check(&arguments)) {
		fprintf(stderr, "Check the -h|--help flag\n");
		return EXIT_FAILURE;
	}

	// Init tinyknock BPF prog + parse CLI arguments
	err = tinyknock_init(config, arguments.file);
	// obj = NULL;
	if (err) {
		goto cleanup;
	}

	// Check if the network interface exist
	ifindex = if_nametoindex(arguments.ifname);
    if (!ifindex) {
        printf("get ifindex from interface name failed\n");
        return EXIT_FAILURE;
    }

	// Load then attach the XDP prog
	err = xdp_init(ifindex, arguments.bpf_object_file);
	if (err) {
		goto cleanup;
	}

	// After the configuration has been loaded
	cyaml_free(get_yaml_config(), get_top_schema(), config, 0);

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	while (!end) {
		sleep(0xffffffff);
	};

cleanup:
	tinyknock_bpf__destroy(obj);
	xdp_program__detach(xdp_prog, ifindex, XDP_MODE_SKB, 0);
	xdp_program__close(xdp_prog);

	return err != EXIT_SUCCESS;
}
