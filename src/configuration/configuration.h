#ifndef __CONFIGURATION_H__
#define __CONFIGURATION_H__

#include <cyaml/cyaml.h>

/**
 * @brief Representing a sequence element from a YAML data
 * 
 */
typedef struct sequence_s {
	unsigned short value;
	unsigned int protocol;
} sequence_t;

/**
 * @brief Data required from a YAML data
 * 
 */
typedef struct policy_s {
	unsigned short target;
	unsigned int action;

	sequence_t *sequence;
	unsigned int sequence_count;
} policy_t;

/**
 * @brief Top YAML data structure
 * 
 */
typedef struct configuration_s {
	policy_t *policies;
	unsigned int policies_count;
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
