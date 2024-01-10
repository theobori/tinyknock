#include <stdlib.h>
#include <stdio.h>

#include <xdp/libxdp.h>
#include <linux/in.h>

#include "configuration.h"

/**
 * @brief Mapping action as string with its values
 * 
 */
static const cyaml_strval_t action_strings[] = {
	{ "open", XDP_PASS },
	{ "close", XDP_DROP },
	{ "abort", XDP_ABORTED }
};

/**
 * @brief Mapping protocol as string with its values
 * 
 */
static const cyaml_strval_t protocol_strings[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "icmp", IPPROTO_ICMP }
};

/**
 * @brief Sequence schema field
 * 
 */
static const cyaml_schema_field_t sequence_fields_schema[] = {
	CYAML_FIELD_UINT(
			"value", CYAML_FLAG_DEFAULT,
			sequence_t, value),
		
	CYAML_FIELD_ENUM(
			"protocol", CYAML_FLAG_DEFAULT,
			sequence_t, protocol, protocol_strings,
			CYAML_ARRAY_LEN(protocol_strings)),

	CYAML_FIELD_END
};

/**
 * @brief Sequence schema values
 * 
 */
static const cyaml_schema_value_t sequence_value_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
			sequence_t, sequence_fields_schema),
};

/**
 * @brief Policy schema fields
 * 
 */
static const cyaml_schema_field_t policy_fields_schema[] = {
	CYAML_FIELD_SEQUENCE(
			"sequence", CYAML_FLAG_POINTER,
			policy_t, sequence,
			&sequence_value_schema, 0, CYAML_UNLIMITED),

	CYAML_FIELD_ENUM(
			"action", CYAML_FLAG_DEFAULT,
			policy_t, action, action_strings,
			CYAML_ARRAY_LEN(action_strings)),
	
	CYAML_FIELD_UINT(
			"target", CYAML_FLAG_DEFAULT,
			policy_t, target),

	CYAML_FIELD_END
};

/**
 * @brief Policy schema values
 * 
 */
static const cyaml_schema_value_t policy_value_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
			policy_t, policy_fields_schema),
};

/**
 * @brief Top schema fields
 * 
 */
static const cyaml_schema_field_t top_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
			"policies", CYAML_FLAG_POINTER,
			configuration_t, policies,
			&policy_value_schema, 0, CYAML_UNLIMITED),
	
	CYAML_FIELD_END
};

/**
 * @brief Top schema values
 * 
 */
static const cyaml_schema_value_t top_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER,
			configuration_t, top_mapping_schema),
};

/**
 * @brief YAML configuration
 * 
 */
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
