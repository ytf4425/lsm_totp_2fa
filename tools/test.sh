#!/bin/bash

exe() {
    echo "\$ $@"
    "$@"
}

echo -e "\033[1mUnlock config file first.\033[0m"
echo -n -e "\033[1mPlease input 2FA token for /etc/security/2fa.conf:\033[0m"
read config_token
exe python3 2fa.py unlock /etc/security/2fa.conf $config_token -1

testfile=$1
echo -e "\033[1mTry to access ${testfile}.\033[0m"
exe cat ${testfile}
echo -e "\033[1mCurrent user's uid is $UID.\033[0m"
echo -e "\033[1mProtect ${testfile} with 2fa(for only current user).\033[0m"
exe sudo python3 2fa.py add ${testfile} $UID
echo -e "\033[1mCheck config file with root user.\033[0m"
exe sudo cat /etc/security/2fa.conf
echo -e "\033[1mQuery the lock state.\033[0m"
exe python3 2fa.py query ${testfile} $UID
echo -e "\033[1mTry to access ${testfile} again with current user and root user.\033[0m"
exe cat ${testfile}
exe sudo cat ${testfile}

echo -e "\033[1mProtect ${testfile} with 2fa(for all users).\033[0m"
exe sudo python3 2fa.py add ${testfile} -1
echo -e "\033[1mCheck config file with root user.\033[0m"
exe sudo cat /etc/security/2fa.conf

echo -n -e "\033[1mUnlock ${testfile} for current user. Please input 2FA token for ${testfile}:\033[0m"
read test_token
exe python3 2fa.py unlock ${testfile} $test_token $UID
echo -e "\033[1mTry to access ${testfile} again with current user and root user.\033[0m"
exe cat ${testfile}
exe sudo cat ${testfile}
echo -e "\033[1mQuery the lock state.\033[0m"
exe python3 2fa.py query ${testfile} $UID
echo -e "\033[1mLock it.\033[0m"
exe python3 2fa.py lock ${testfile}
echo -e "\033[1mTry to access ${testfile} again with current user.\033[0m"
exe cat ${testfile}
echo -n -e "\033[1mDelete 2fa entry. Please input 2FA token for ${testfile}(current user):\033[0m"
read test_token
exe sudo python3 2fa.py delete ${testfile} -u $UID -c $test_token
echo -n -e "\033[1mDelete 2fa entry. Please input 2FA token for ${testfile}(all users):\033[0m"
read test_token
exe sudo python3 2fa.py delete ${testfile} -u -1 -c $test_token
echo -e "\033[1mCheck config file with root user.\033[0m"
exe sudo cat /etc/security/2fa.conf
echo -e "\033[1mTry to access ${testfile} again with current user and root user.\033[0m"
exe cat ${testfile}
exe sudo cat ${testfile}
