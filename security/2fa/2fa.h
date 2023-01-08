#ifndef _2FA_H
#define _2FA_H

#define UNLOCKED 0
#define LOCKED 1

#define UNLOCK 0
#define LOCK 1
#define ADD 2
#define DELETE 3

#include <linux/hashtable.h>
#include <linux/fs.h>

struct file_node {
    struct hlist_node node;
    int hash_value;
    char* path;
    char* code;
    int uid;
    int state;
};

void init_hashtable(void);
void load_config(void);
struct file_node* get_file_info(const char* path, int uid);
int check_permission(char* path, int uid);
int execute_command(struct file_node* file_info, int new_state, const char* path, const char* key, int uid);

// extern struct file *conf_file;

#endif
