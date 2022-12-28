#include <linux/hashtable.h>
#include "otp/base32.h"
#include "otp/rfc6238.h"
#include "2fa.h"

void init_hashlist(){

}

char* get_new_2fa_code(){
    time64_t timenow=get_time(T0);
    
}