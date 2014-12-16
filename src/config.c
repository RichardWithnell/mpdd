/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Author: Richard Withnell
    github.com/richardwithnell
*/

#include <stdlib.h>
#include <stdio.h>
#include <libconfig.h>
#include <errno.h>
#include <error.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "util.h"

#define MAX_LINE_SIZE 512

#if (((LIBCONFIG_VER_MAJOR == 1) && (LIBCONFIG_VER_MINOR >= 4)) \
    || (LIBCONFIG_VER_MAJOR > 1))
/* use features present in libconfig 1.4 and later */
#endif

/*Quick and dirty, should realloc xbytes instead of alloc max_size*/
int readline(char **line, size_t* max_size, FILE *fp)
{
    char c = 0;
    int size = *max_size;
    char *ptr = (char*)0;
    *line = malloc(sizeof(char) * size);

    ptr = *line;

    if(!line){
        return 0;
    }

    if(max_size <= 0){
        return 0;
    }

    if(!fp){
        return -1;
    }

    while((c = fgetc(fp)) != '\n' && c != EOF && (ptr-*line) < size-1){
        *ptr++ = c;
    }

    *ptr = '\0';
    return (int)(ptr-*line);
}

struct mpd_config * load_min_config(char *path)
{
    FILE *fp;
    char *host_id = (char*)0;
    char *line_in = (char*)0;
    char *tok = (char*)0;
    int max_size = MAX_LINE_SIZE;
    struct mpd_config *mpd = (struct mpd_config*)0;
    int read = 0;
    List *ignore = (List*)0;
    List *diss = (List*)0;

    if(!path){
        print_debug("Failed to load config, path is NULL.\n");
        return 0;
    }

    if(!(line_in = malloc(MAX_LINE_SIZE))) {
        print_error("Failed to allocate memory for line_in\n");
        errno = ENOMEM;
        return 0;
    }

    if(!(host_id = malloc(MAX_HOST_ID_SIZE))) {
        print_error("Failed to allocate memory for host_id\n");
        errno = ENOMEM;
        return 0;
    }

    if(!(mpd = malloc(sizeof(struct mpd_config)))){
        print_error("Failed to allocate memory for mpd config\n");
        errno = ENOMEM;
        return 0;
    }

    mpd->host = 0;
    mpd->diss = (List*)0;
    mpd->ignore = (List*)0;

    if(!(ignore = malloc(sizeof(List)))) {
        print_error("Failed to allocate memory for ignore interface list\n");
        errno = ENOMEM;
        free(mpd);
        return 0;
    }

    if(!(diss = malloc(sizeof(List)))) {
        print_error("Failed to allocate memory for diss interface list\n");
        errno = ENOMEM;
        free(ignore);
        free(mpd);
        return 0;
    }

    fp = fopen(path, "r"); // read mode
    if(!fp){
        print_error("Failed to open config file: %s\n", path);
        return 0;
    }

    list_init(ignore);
    list_init(diss);

    /*Read Hostname*/
    memset(line_in, 0, MAX_LINE_SIZE);
    memset(host_id, 0, MAX_HOST_ID_SIZE);

    read = readline(&line_in, (size_t*)&max_size, fp);
    if(!read){
        print_debug("Failed parsing file\n");
        return 0;
    }

    char *strptr = line_in;
    strptr = trimwhitespace(strptr);
    memcpy(host_id, strptr, strlen(strptr));
    print_debug("ID: %s\n", host_id);

    /*Read Dissemination Interfaces*/
    memset(line_in, 0, MAX_LINE_SIZE);
    read = readline(&line_in, (size_t*)&max_size, fp);
    if(!read){
        print_debug("Failed parsing file\n");
        return 0;
    }
    tok = strtok(line_in, ",");
    while(tok) {
        Litem *item = (Litem*)0;
        //tok = trimwhitespace(tok);
        if(!(item = malloc(sizeof(Litem)))){
            list_destroy(ignore);
            list_destroy(diss);
            free(mpd);
            errno = ENOMEM;
            return 0;
        }

        if(!(item->data = malloc(strlen(tok)+1))){
            free(item);
            free(ignore);
            free(diss);
            free(mpd);
            errno = ENOMEM;
            return 0;
        }

        memset(item->data, 0, strlen(tok)+1);
        strncpy(item->data, tok, strlen(tok));
        list_put(diss, item);
        print_debug("Diss Iff: %s\n", tok);
        tok = strtok (NULL, ",");
    }

    /*Read Ignore Interfaces*/
    memset(line_in, 0, MAX_LINE_SIZE);
    read = readline(&line_in, (size_t*)&max_size, fp);
    if(!read){
        print_debug("Failed parsing file\n");
        return 0;
    }
    tok = strtok(line_in, ",");
    while(tok) {
        Litem *item = (Litem*)0;
        //tok = trimwhitespace(tok);
        if(!(item = malloc(sizeof(Litem)))){
            list_destroy(ignore);
            list_destroy(diss);
            free(mpd);
            errno = ENOMEM;
            return 0;
        }

        if(!(item->data = malloc(strlen(tok)+1))){
            free(item);
            free(ignore);
            free(diss);
            free(mpd);
            errno = ENOMEM;
            return 0;
        }

        memset(item->data, 0, strlen(tok)+1);
        strncpy(item->data, tok, strlen(tok));
        list_put(ignore, item);
        print_debug("Ignore Iff: %s\n", tok);

        tok = strtok (NULL, ",");
    }

    memcpy(mpd->host_id, host_id, MAX_HOST_ID_SIZE-1);
    mpd->host = 1;
    mpd->ignore = ignore;
    mpd->diss = diss;
    print_debug("Config Loaded\n");

    free(line_in);
    free(host_id);

    return mpd;
}


/**
*
*/
struct mpd_config * load_config(char *path)
{
    const char *host_id;
    struct mpd_config *mpd = (struct mpd_config*)0;
    config_t *conf = (config_t*)0;
    config_t cfg;
    config_setting_t *setting = (config_setting_t*)0;
    int host = 0;
    int count = 0;
    int i = 0;
    List *ignore = (List*)0;
    List *diss = (List*)0;

    if(!path){
        print_debug("Failed to load config, path is NULL.\n");
        return 0;
    }

    if(!(mpd = malloc(sizeof(struct mpd_config)))){
        print_error("Failed to allocate memory for diss interface list\n");
        errno = ENOMEM;
        return 0;
    }

    mpd->host = 0;
    mpd->diss = (List*)0;
    mpd->ignore = (List*)0;

    if(!(ignore = malloc(sizeof(List)))) {
        print_error("Failed to allocate memory for ignore interface list\n");
        errno = ENOMEM;
        free(mpd);
        return 0;
    }

    if(!(diss = malloc(sizeof(List)))) {
        print_error("Failed to allocate memory for diss interface list\n");
        errno = ENOMEM;
        free(ignore);
        free(mpd);
        return 0;
    }

    conf = &cfg; /*Filthy*/
    config_init (conf);

    if(!conf){
        print_error("Config file is null.");
        return 0;
    }

    if(config_read_file(conf, path) == CONFIG_FALSE){
        print_error("Failed parsing config: %s : %d : %s : %d\n",
             config_error_file(conf),
             config_error_line(conf),
             config_error_text(conf),
             (int)config_error_type(conf));
        free(ignore);
        free(diss);
        free(mpd);
        return 0;
    }

    if(config_lookup_string(conf, "host_id", &host_id) == CONFIG_FALSE){
        print_debug("No host_id value, using default\n");

        //strcpy(host_id, "def_host\0");
    }

    if(config_lookup_bool(conf, "application.host", &host) == CONFIG_FALSE){
        print_debug("No host value, using default\n");
    }
    print_debug("Host set to %d\n", host);

    list_init(ignore);

    if((setting = config_lookup(conf, "application.ignore"))){
        print_debug("Parsing ignore interfaces\n");
        count = config_setting_length(setting);
        for (i = 0; i < count; i++) {
            Litem *item = (Litem*)0;
            const char *iffname = config_setting_get_string_elem(setting, i);
            if(!iffname){
                break;
            }

            if(!(item = malloc(sizeof(Litem)))){
                list_destroy(ignore);
                list_destroy(diss);
                free(mpd);
                errno = ENOMEM;
                return 0;
            }

            if(!(item->data = malloc(strlen(iffname)+1))){
                free(item);
                free(ignore);
                free(diss);
                free(mpd);
                errno = ENOMEM;
                return 0;
            }

            memset(item->data, 0, strlen(iffname)+1);
            strncpy(item->data, iffname, strlen(iffname));
            list_put(ignore, item);

            print_debug("  Diss (%d) %s\n", i+1, iffname);
        }
    } else {
        print_debug("No interfaces to ignore have been specified\n");
    }

    list_init(diss);

    if((setting = config_lookup(conf, "application.dissemination"))){
        print_debug("Parsing dissemination interfaces\n");
        count = config_setting_length(setting);
        for (i = 0; i < count; i++) {
            Litem *item= (Litem*)0;
            const char *iffname = config_setting_get_string_elem(setting, i);
            if(!iffname){
                break;
            }

            if(!(item = malloc(sizeof(Litem)))){
                list_destroy(ignore);
                list_destroy(diss);
                free(mpd);
                errno = ENOMEM;
                return 0;
            }

            if(!(item->data = malloc(strlen(iffname)+1))){
                free(item);
                free(ignore);
                free(diss);
                free(mpd);
                errno = ENOMEM;
                return 0;
            }

            memset(item->data, 0, strlen(iffname)+1);
            strncpy(item->data, iffname, strlen(iffname));
            list_put(diss, item);

            print_debug("  Diss (%d) %s\n", i+1, iffname);
        }
    } else {
        print_debug("No interfaces to disseminate onto have been specified\n");
    }

    config_destroy(conf);

    memcpy(mpd->host_id, host_id, 16);
    mpd->host = host;
    mpd->ignore = ignore;
    mpd->diss = diss;

    return mpd;
}

/* end file: config.c */
