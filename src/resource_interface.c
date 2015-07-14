#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "resource_interface.h"
#include "debug.h"

#define RESOURCE_INTERFACE_PATH "/tmp/mpdd/"
#define RESOURCE_INTERFACE_PATH_DIRECT "direct/"
#define RESOURCE_INTERFACE_PATH_INDIRECT "indirect/"


int ensure_dir_exists(char *path)
{
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        return mkdir(path, 0700);
    }
    return 0;
}

int create_type_file(uint32_t ip, char *type, int resource_location)
{
    char folder_path[512];
    char file_path[512];
    FILE *fp;
    memset(folder_path, 0, 512);
    ensure_dir_exists(RESOURCE_INTERFACE_PATH);
    strcpy(folder_path, RESOURCE_INTERFACE_PATH);
    switch(resource_location){
        case DIRECT_RESOURCE:
            strcat(folder_path, RESOURCE_INTERFACE_PATH_DIRECT);
            break;
        case INDIRECT_RESOURCE:
            strcat(folder_path, RESOURCE_INTERFACE_PATH_INDIRECT);
            break;
        default:
            print_error("Unknown resource location\n");
            return -1;
    }
    ensure_dir_exists(folder_path);
    sprintf(file_path, "%s%lu_type", folder_path, ip);
    fp = fopen(file_path, "w+");
    fprintf(fp, "%s\n", type);
    fclose(fp);
    return 0;
}

int create_table_file(uint32_t ip, int table, int resource_location)
{
    char folder_path[512];
    char file_path[512];
    FILE *fp;
    memset(folder_path, 0, 512);
    ensure_dir_exists(RESOURCE_INTERFACE_PATH);
    strcpy(folder_path, RESOURCE_INTERFACE_PATH);
    switch(resource_location){
        case DIRECT_RESOURCE:
            strcat(folder_path, RESOURCE_INTERFACE_PATH_DIRECT);
            break;
        case INDIRECT_RESOURCE:
            strcat(folder_path, RESOURCE_INTERFACE_PATH_INDIRECT);
            break;
        default:
            print_error("Unknown resource location\n");
            return -1;
    }
    ensure_dir_exists(folder_path);
    sprintf(file_path, "%s%zu_table", folder_path, ip);
    fp = fopen(file_path, "w+");
    fprintf(fp, "%d\n", table);
    fclose(fp);
    return 0;
}

int delete_table_file(uint32_t ip, int resource_location)
{
    char folder_path[512];
    switch(resource_location){
        case DIRECT_RESOURCE:
            sprintf(folder_path, "%s%s%zu_table", RESOURCE_INTERFACE_PATH, RESOURCE_INTERFACE_PATH_DIRECT, ip);
            break;
        case INDIRECT_RESOURCE:
        sprintf(folder_path, "%s%s%zu_table", RESOURCE_INTERFACE_PATH, RESOURCE_INTERFACE_PATH_INDIRECT, ip);
            break;
        default:
            print_error("Unknown resource location\n");
            return -1;
    }
    return remove(folder_path);
}

int delete_type_file(uint32_t ip, int resource_location)
{
    char folder_path[512];
    switch(resource_location){
        case DIRECT_RESOURCE:
            sprintf(folder_path, "%s%s%zu_type", RESOURCE_INTERFACE_PATH, RESOURCE_INTERFACE_PATH_DIRECT, ip);
            break;
        case INDIRECT_RESOURCE:
        sprintf(folder_path, "%s%s%zu_type", RESOURCE_INTERFACE_PATH, RESOURCE_INTERFACE_PATH_INDIRECT, ip);
            break;
        default:
            print_error("Unknown resource location\n");
            return -1;
    }
    return remove(folder_path);
}

int delete_resource_folder(uint32_t ip, int resource_location)
{
    char folder_path[512];
    switch(resource_location){
        case DIRECT_RESOURCE:
            sprintf(folder_path, "%s%s", RESOURCE_INTERFACE_PATH, RESOURCE_INTERFACE_PATH_DIRECT);
            break;
        case INDIRECT_RESOURCE:
        sprintf(folder_path, "%s%s", RESOURCE_INTERFACE_PATH, RESOURCE_INTERFACE_PATH_INDIRECT);
            break;
        default:
            print_error("Unknown resource location\n");
            return -1;
    }
    return rmdir(folder_path);
}
