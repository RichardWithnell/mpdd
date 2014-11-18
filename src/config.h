#include "list.h"

struct mpd_config {
    List *ignore;
    List *diss;
    int host;
};

struct mpd_config * load_config(char *path);

/* end file: config.h */
