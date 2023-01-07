import sys
import os


def write_file(path, uid, command, code=None):
    with open('/proc/2fa/path', 'w') as f:
        f.write(path)
    if code is not None:
        with open('/proc/2fa/code', 'w') as f:
            f.write(code)
    with open('/proc/2fa/uid', 'w') as f:
        f.write(uid)
    with open('/proc/2fa/state', 'w') as f:
        f.write(command)


def lock(path, uid=os.geteuid()):
    try:
        write_file(path=path, command=1, uid=uid)
    except:
        print('lock failed: path is {}, uid is {}.'.format(path, uid))


def unlock(path, code, uid=os.geteuid()):
    try:
        write_file(path=path, code=code, command=0, uid=uid)
    except:
        print('unlock failed: path is {}, uid is {}.'.format(path, uid))


def query(path, uid=os.geteuid()):
    with open('/proc/2fa/path', 'w') as f:
        f.write(path)
    with open('/proc/2fa/uid', 'w') as f:
        f.write(uid)
    with open('/proc/2fa/state', 'r') as f:
        try:
            print(f.read())
        except:
            print('query failed: path is {}, uid is {}.'.format(path, uid))


def delete(path, uid=os.geteuid(), code=None):
    try:
        write_file(path=path, code=code, command=3, uid=uid)
    except:
        print('delete failed: path is {}, uid is {}.'.format(path, uid))


def new_2fa_code():
 pass


def add(path, uid=os.geteuid()):
    try:
        write_file(path=path, code=new_2fa_code(), command=2, uid=uid)
    except:
        print('add failed: path is {}, uid is {}.'.format(path, uid))


def print_err():
    print("error: wrong args number.")
    print("usage: python " + sys.argv[0] + " { lock | query } path [uid]")
    print("       python " + sys.argv[0] + " unlock path 2fa_code [uid]")
    print("       python " + sys.argv[0] + " add path [uid]")
    print("       python " + sys.argv[0] + " delete path [2fa_code uid]")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        if sys.argv[1] == 'query':
            query(sys.argv[2])
        elif sys.argv[1] == 'lock':
            lock(sys.argv[2])
        elif sys.argv[1] == 'add':
            add(sys.argv[2])
        else:
            print_err()
    elif len(sys.argv) == 4:
        if sys.argv[1] == 'unlock':
            unlock(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == 'add':
            add(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == 'delete':
            delete(sys.argv[2], sys.argv[3])
        else:
            print_err()
    elif len(sys.argv) == 5:
        if sys.argv[1] == 'unlock':
            unlock(sys.argv[2], sys.argv[3], sys.argv[4])
        elif sys.argv[1] == 'delete':
            delete(sys.argv[2], sys.argv[4], sys.argv[3])
        else:
            print_err()
    else:
        print_err()
