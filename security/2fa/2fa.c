#include "2fa.h"
#include <linux/string.h>

struct hlist_head htable[16];
EXPORT_SYMBOL(htable);

int hash_calc(const char* str);

void init_hashtable(void)
{
    hash_init(htable);
}

int hash_calc(const char* str)
{
    int i, ret;
    for (i = 0, ret = 0; str[i] != 0; i++) {
        ret += str[i];
    }
    return ret;
}

int check_permission(char* path, int uid)
{
    int hash_value = hash_calc(path);
    struct file_node* file_entry;
    int state = UNLOCKED;

    hash_for_each_possible(htable, file_entry, node, hash_value)
    {
        if (file_entry->hash_value != hash_value)
            continue;
        if (strcmp(file_entry->path, path) != 0)
            continue;

        if (file_entry->uid == uid) {
            pr_info("[2fa_lsm] pemission denied: access %s with uid %d.\n", path, uid);
            return file_entry->state; // exact match first
        } else if (file_entry->uid == -1){
            state = file_entry->state;
            if (state == LOCKED)
                pr_info("[2fa_lsm] access pemission denied %s for all unspecified users, but it may be accessible for user %d\n", path, uid);
        }
    }
    return state;
}

EXPORT_SYMBOL(hash_calc);