#include "list.h"

struct mpd_config {
    List *ignore;
    List *diss;
    char host_id[16];
    int host;
};

struct mpd_config * load_config(char *path);

/* end file: config.h */
