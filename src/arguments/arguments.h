#ifndef __ARGUMENTS_H__
#define __ARGUMENTS_H__

#include <stdbool.h>

/**
 * @brief CLI description
 * 
 */
#define DESCRIPTION "\nA brief description of what the program does and how it works."

/**
 * @brief Represents the CLI arguments
 * 
 */
typedef struct arguments_s {
    char *ifname;
    char *file;
    char *bpf_object_file;
    unsigned int xdp_prog_id;
} arguments_t;

/**
 * @brief Parse CLI arguments
 * 
 * @param arguments 
 * @param argc 
 * @param argv 
 */
void arguments_parse(arguments_t *arguments, int argc, const char *argv[]);

/**
 * @brief Parse CLI arguments and return the associated needed data
 * 
 * @param argc 
 * @param argv 
 * @return arguments_t 
 */
arguments_t arguments_create_and_parse(int argc, const char *argv[]);

/**
 * @brief Verify if the arguments have the data it requires
 * 
 * @param arguments 
 * @return true 
 * @return false 
 */
bool arguments_check(arguments_t *arguments);

#endif
