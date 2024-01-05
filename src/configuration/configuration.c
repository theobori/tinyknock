#include <stdlib.h>
#include <stdio.h>

#include "configuration.h"

static const cyaml_schema_field_t top_mapping_schema[] = {
	CYAML_FIELD_END
};

static const cyaml_schema_value_t top_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER,
			configuration_t, top_mapping_schema),
};

static const cyaml_config_t yaml_config = {
	.log_fn = cyaml_log,
	.mem_fn = cyaml_mem,
	.log_level = CYAML_LOG_WARNING,
};

const cyaml_config_t *get_yaml_config()
{
	return &yaml_config;
}

const cyaml_schema_value_t *get_top_schema()
{
	return &top_schema;
}

int tinyknock_configuration_init(configuration_t **config, const char *path)
{
	cyaml_err_t err;

	if (!path) {
		fprintf(stderr, "missing YAML file\n");
		return EXIT_FAILURE;
	}

	err = cyaml_load_file(path, &yaml_config,
			&top_schema, (cyaml_data_t **)config, NULL);
	
	if (err != CYAML_OK) {
		fprintf(stderr, "%s\n", cyaml_strerror(err));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
