#ifndef _2FA_H
#define _2FA_H

#define LOCKED 0
#define UNLOCKED 1

#define LOCK 0
#define UNLOCK 1
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
struct file_node* get_file_info(char* path, int uid);
int hash_calc(char* str);
int unlock(struct file_node* file_info, char* key);
int lock(struct file_node* file_info);
int totp(char* key);
char* get_new_2fa_code(void);
void insert_new_entry(char* path, char* code, int uid);
void insert_entry(struct file_node* new_file_entry);
void delete_entry(struct file_node* now_file);

// extern struct file *conf_file;

#endif
