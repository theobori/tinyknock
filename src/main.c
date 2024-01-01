#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cyaml/cyaml.h>

#include "tinyknock.skel.h"
#include "configuration.h"

#define ARG_PROG_NAME 0
#define ARG_COUNT 2

int main(int argc, char *argv[])
{
	struct tinyknock_bpf *obj = NULL;
	configuration_t *config = NULL;
	int err;
	int fd;

	// check the CLI arguments
	if (argc != ARG_COUNT) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "  %s <path>\n", argv[ARG_PROG_NAME]);
		
		return EXIT_FAILURE;
	}

    // Open and load the BPF program,
    // see bytecode in the skeleton header
	obj = tinyknock_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		
		return 1;
	}

    // Attach the program
	err = tinyknock_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		
		goto cleanup;
	}

	// Load the YAML configuration
	err = tinyknock_configuration_init(&config, argv[1]);
	if (err) {
		goto cleanup;
	}


	// After the configuration has been loaded
	cyaml_free(get_yaml_config(), get_top_schema(), config, 0);

	while (1) {
		sleep(2);
	};

cleanup:
	tinyknock_bpf__destroy(obj);
	return EXIT_FAILURE;
}
