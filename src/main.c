#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <xdp/libxdp.h>

#include <cyaml/cyaml.h>

#include "./configuration/configuration.h"
#include "./arguments/arguments.h"
#include "./rule/rule.h"

#define ARG_COUNT 2
#define XDP_SECTION_NAME "xdp"

/**
 * @brief BPF object
 * 
 */
static struct bpf_object *obj = NULL;
/**
 * @brief XDP program
 * 
 */
static struct xdp_program *xdp_prog = NULL;

static void int_exit(int sig)
{
	xdp_program__close(xdp_prog);

	exit(0);
}

static int tinyknock_init(configuration_t *config, char *filename)
{
	int err;

	// Load the YAML configuration
	err = tinyknock_configuration_init(&config, filename);
	if (err) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int xdp_init(unsigned int ifindex, char *filename) {
	int err;

	if (!filename) {
		return EXIT_FAILURE;
	}

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
		return err;
	}

	// Get the BPF object for later
	obj = xdp_program__bpf_obj(xdp_prog);
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object from XDP program\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int xdp_detach(unsigned int ifindex, unsigned int xdp_prog_id)
{
	return xdp_program__detach(
		xdp_program__from_id(xdp_prog_id), ifindex, XDP_MODE_SKB, 0
	);
}

int main(int argc, const char *argv[])
{
	int err, xfsm_fd;
	
	unsigned int ifindex = 0;
	configuration_t *config = NULL;
	arguments_t arguments = arguments_create_and_parse(argc, argv);
	
	if (argc < ARG_COUNT || !arguments_check(&arguments)) {
		fprintf(stderr, "Check the -h|--help flag\n");
		return EXIT_FAILURE;
	}

	// Check if the network interface exist
	ifindex = if_nametoindex(arguments.ifname);
	if (!ifindex) {
		printf("get ifindex from interface name failed\n");
		return EXIT_FAILURE;
	}

	// Detach XDP prog if --detach is set
	if (arguments.xdp_prog_id)
		return xdp_detach(ifindex, arguments.xdp_prog_id);
	
	// Get YAML data
	err = tinyknock_init(config, arguments.file);
	if (err)
		return EXIT_FAILURE;

	// Load then attach the XDP prog and get a BPF obj
	err = xdp_init(ifindex, arguments.bpf_object_file);
	if (err)
		return EXIT_FAILURE;
	
	// Fill XFSM
	xfsm_fd = bpf_object__find_map_fd_by_name(obj, "xfsm");
	if (xfsm_fd < 0)
		return EXIT_FAILURE;

	err = rule_xfsm_fill_bpf_map(xfsm_fd, config);
	if (err)
		return EXIT_FAILURE;

	// After the configuration has been loaded
	cyaml_free(get_yaml_config(), get_top_schema(), config, 0);

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	while (1) {
		sleep(0xffffffff);
	};

	return EXIT_SUCCESS;
}
