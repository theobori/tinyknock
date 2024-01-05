#ifndef __CONFIGURATION_H__
#define __CONFIGURATION_H__

#include <cyaml/cyaml.h>

/**
 * @brief Data required from the YAML
 * 
 */
typedef struct configuration_s {
	char *unused;
} configuration_t;

/**
 * @brief Write on the configuration from the YAML file data
 * 
 * @param config 
 * @param path YAML file
 * @return int 
 */
int tinyknock_configuration_init(configuration_t **config, const char *path);
/**
 * @brief Get the yaml config object
 * 
 * @return const cyaml_config_t* 
 */
const cyaml_config_t *get_yaml_config();
/**
 * @brief Get the top schema object
 * 
 * @return const cyaml_schema_value_t* 
 */
const cyaml_schema_value_t *get_top_schema();

#endif
