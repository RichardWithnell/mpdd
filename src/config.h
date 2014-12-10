#include "list.h"

#define MAX_HOST_ID_SIZE 32

struct mpd_config {
    List *ignore;
    List *diss;
    char host_id[MAX_HOST_ID_SIZE];
    int host;
};

struct mpd_config * load_min_config(char *path);
struct mpd_config * load_config(char *path);

/* end file: config.h */
