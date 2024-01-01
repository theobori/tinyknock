#ifndef __CONFIGURATION_H__
#define __CONFIGURATION_H__

#include <cyaml/cyaml.h>

typedef struct configuration_s {
	char *network_interface;
} configuration_t;

int tinyknock_configuration_init(configuration_t **config, char *path);

const cyaml_config_t *get_yaml_config();
const cyaml_schema_value_t *get_top_schema();

#endif
