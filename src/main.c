#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <errno.h>
#include <signal.h>

#include <xdp/libxdp.h>
#include <bpf/libbpf.h>
#include <cyaml/cyaml.h>

#include "./configuration/configuration.h"
#include "./arguments/arguments.h"
#include "./rule/rule.h"
#include "./event/sequence_event.h"

#define ARG_COUNT 2
#define XDP_SECTION_NAME "xdp"

/**
 * @brief Used to manage the main loop
 * 
 */
static bool running = true;

/**
 * @brief Handles UNIX signal that should exit the program
 * 
 * @param sig 
 */
static void sig_exit_handler(int sig)
{
	running = false;
}

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

/**
 * @brief Callback used for `sequence_rb` ring buffer
 * 
 * @param ctx 
 * @param data 
 * @param data_sz 
 * @return int 
 */
int handle_event(void *ctx, void *data, size_t data_sz)
{
	const sequence_event_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf(
		"%-8s Step %d, knocking on port %hu with protocol %d\n",
		ts, e->step, e->port, e->protocol
	);

	if (e->is_target)
		printf("%-8s Triggered port %d\n", ts, e->next_port);

	return 0;
}

/**
 * @brief Init user program (cli) specific things
 * 
 * @param config 
 * @param filename 
 * @return int 
 */
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

/**
 * @brief Init XDP program
 * 
 * @param ifindex 
 * @param filename 
 * @return int 
 */
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

/**
 * @brief Unload / detach XDP program attached to a network interface
 * 
 * @param ifindex 
 * @param xdp_prog_id 
 * @return int 
 */
static int xdp_detach(unsigned int ifindex, unsigned int xdp_prog_id)
{
	return xdp_program__detach(
		xdp_program__from_id(xdp_prog_id), ifindex, XDP_MODE_SKB, 0
	);
}

int main(int argc, const char *argv[])
{
	int err, fd;

	unsigned int ifindex = 0;
	configuration_t *config = NULL;
	struct ring_buffer *rb = NULL;

	arguments_t arguments = arguments_create_and_parse(argc, argv);
	
	if (argc < ARG_COUNT || !arguments_check(&arguments)) {
		fprintf(stderr, "Check the -h|--help flag\n");
		return EXIT_FAILURE;
	}

	// Check if the network interface exist
	ifindex = if_nametoindex(arguments.ifname);
	if (!ifindex) {
		fprintf(stderr, "get ifindex from interface name failed\n");
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
	fd = bpf_object__find_map_fd_by_name(obj, "xfsm");
	if (fd < 0)
		return EXIT_FAILURE;

	err = rule_xfsm_fill_bpf_map(fd, config);
	if (err)
		return EXIT_FAILURE;

	// After the configuration has been loaded
	cyaml_free(get_yaml_config(), get_top_schema(), config, 0);

	fd = bpf_object__find_map_fd_by_name(obj, "sequence_rb");
	rb = ring_buffer__new(fd, handle_event, NULL, NULL);

	signal(SIGINT, sig_exit_handler);
	signal(SIGTERM, sig_exit_handler);

	while (running) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}

		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	};

	xdp_program__close(xdp_prog);

	return EXIT_SUCCESS;
}
