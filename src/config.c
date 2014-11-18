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


#if (((LIBCONFIG_VER_MAJOR == 1) && (LIBCONFIG_VER_MINOR >= 4)) \
    || (LIBCONFIG_VER_MAJOR > 1))
/* use features present in libconfig 1.4 and later */
#endif


/**
*
*/
struct mpd_config * load_config(char *path)
{

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
        fprintf(stderr, "Failed to allocate memory for diss interface list\n");
        errno = ENOMEM;
        return 0;
    }

    mpd->host = 0;
    mpd->diss = (List*)0;
    mpd->ignore = (List*)0;

    if(!(ignore = malloc(sizeof(List)))) {
        fprintf(stderr, "Failed to allocate memory for ignore interface list\n");
        errno = ENOMEM;
        free(mpd);
        return 0;
    }

    if(!(diss = malloc(sizeof(List)))) {
        fprintf(stderr, "Failed to allocate memory for diss interface list\n");
        errno = ENOMEM;
        free(ignore);
        free(mpd);
        return 0;
    }

    conf = &cfg; /*Filthy*/
    config_init (conf);

    if(config_read_file(conf, path) == CONFIG_FALSE){
        print_debug("Failed to parse config file.\n");
        fprintf(stderr, "Failed parsing config: %s : %d : %s\n",
             config_error_file(conf),
             config_error_line(conf),
             config_error_text(conf));
        free(ignore);
        free(diss);
        free(mpd);
        return 0;
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

    mpd->host = host;
    mpd->ignore = ignore;
    mpd->diss = diss;

    return mpd;
}

/* end file: config.c */
