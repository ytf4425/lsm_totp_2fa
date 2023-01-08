#ifndef _LSM_2FA_H
#define _LSM_2FA_H

#define UNLOCKED 0
#define LOCKED 1

#include <linux/hashtable.h>

struct file_node {
    struct hlist_node node;
    int hash_value;
    char* path;
    char* code;
    int uid;
    int state;
};

void init_hashtable(void);
int check_permission(char* path, int uid);

#endif
