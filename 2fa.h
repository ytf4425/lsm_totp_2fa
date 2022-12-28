#ifndef _2FA_H
#define _2FA_H

#define LOCKED 0
#define UNLOCKED 1

struct file_node {
    struct hlist_node node;
    char* path;
    char* code;
    int uid;
    int state;
};

#endif
