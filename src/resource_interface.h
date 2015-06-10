#ifndef MPDD_RESOURCE_INTERFACE
#define MPDD_RESOURCE_INTERFACE

#include <stdint.h>

enum {
    DIRECT_RESOURCE,
    INDIRECT_RESOURCE,
    UNKNOWN_RESOURCE
};

int create_type_file(uint32_t ip, char *type, int resource_location);
int create_table_file(uint32_t ip, int table, int resource_location);
int delete_table_file(uint32_t ip, int resource_location);
int delete_type_file(uint32_t ip, int resource_location);
int delete_resource_folder(uint32_t ip, int resource_location);

#endif
