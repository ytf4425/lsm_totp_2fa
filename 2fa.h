#ifndef _2FA_H
#define _2FA_H

#define LOCKED 0
#define UNLOCKED 1

#include <linux/hashtable.h>

struct file_node {
    struct hlist_node node;
    char* path;
    char* code;
    int uid;
    int state;
};

int unlock(struct file_node* file_info, char* key);
int lock(struct file_node* file_info);
int totp(char* key);
char* get_new_2fa_code(void);
void init_2fa(void);

#endif
