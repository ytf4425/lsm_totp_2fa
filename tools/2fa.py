import sys
import os


def write_file(path, uid, command, code=None):
    if os.path.isabs(path) == False:
        path = os.path.abspath(path)
    with open('/proc/2fa/path', 'w') as f:
        f.write(path)
    if code is not None:
        with open('/proc/2fa/key', 'w') as f:
            f.write(code)
    with open('/proc/2fa/uid', 'w') as f:
        f.write(uid)
    with open('/proc/2fa/state', 'w') as f:
        f.write(command)


def lock(path, uid=str(os.geteuid())):
    try:
        write_file(path=path, command="1", uid=uid)
    except:
        print('lock failed: path is {}, uid is {}.'.format(path, uid))


def unlock(path, code, uid=str(os.geteuid())):
    try:
        write_file(path=path, code=code, command="0", uid=uid)
    except:
        print('unlock failed: path is {}, uid is {}.'.format(path, uid))


def query(path, uid=str(os.geteuid())):
    if os.path.isabs(path) == False:
        path = os.path.abspath(path)
    with open('/proc/2fa/path', 'w') as f:
        f.write(path)
    with open('/proc/2fa/uid', 'w') as f:
        f.write(uid)
    with open('/proc/2fa/state', 'r') as f:
        try:
            print(f.read())
        except:
            print('query failed: path is {}, uid is {}.'.format(path, uid))


def delete(path, uid=str(os.geteuid()), code=None):
    try:
        write_file(path=path, code=code, command="3", uid=uid)
    except:
        print('delete failed: path is {}, uid is {}.'.format(path, uid))
        print("If you have not unlocked the configuration file, please unlock /etc/security/2fa.conf first.")
        print("If you do not have the access to config file after unlocking it, please switch to root user.")


def new_2fa_code(path, uid):
    import base64
    import random
    import segno
    new_code = str(base64.b32encode(random.randbytes(20)), 'utf-8')
    qr = "otpauth://totp/{label}?secret={secret}&issuer={issuer}".format(
        label=path.replace('/', '_')+"_"+uid, secret=new_code, issuer="lsm_2fa")

    print("Scan the QR Code with your 2fa authenticator.")
    segno.make(qr).terminal(border=1)
    print("\nYou can also manully add to 2fa authenticator with code:\n{code}".format(
        code=new_code))
    return new_code


def add(path, uid=str(os.geteuid())):
    try:
        write_file(path=path, code=new_2fa_code(
            path, uid), command="2", uid=uid)
    except:
        print('add failed: path is {}, uid is {}.'.format(path, uid))
        print("If you have not unlocked the configuration file, please unlock /etc/security/2fa.conf first.")
        print("If you do not have the access to config file after unlocking it, please switch to root user.")


def print_err():
    print("error: wrong args number.")
    print("usage: python " + sys.argv[0] +
          " { lock | query | add } path [uid]")
    print("       python " + sys.argv[0] + " unlock path 2fa_code [uid]")
    print("       python " + sys.argv[0] +
          " delete path [-c 2fa_code] [-u uid]")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        if sys.argv[1] == 'query':
            query(sys.argv[2])
        elif sys.argv[1] == 'lock':
            lock(sys.argv[2])
        elif sys.argv[1] == 'add':
            add(sys.argv[2])
        elif sys.argv[1] == 'delete':
            delete(sys.argv[2])
        else:
            print_err()
    elif len(sys.argv) == 4:
        if sys.argv[1] == 'unlock':
            unlock(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == 'query':
            query(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == 'lock':
            lock(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == 'add':
            add(sys.argv[2], sys.argv[3])
        else:
            print_err()
    elif len(sys.argv) == 5:
        if sys.argv[1] == 'unlock':
            unlock(sys.argv[2], sys.argv[3], sys.argv[4])
        elif sys.argv[1] == 'delete':
            if sys.argv[3] == '-c':
                delete(sys.argv[2], code=sys.argv[4])
            elif sys.argv[3] == '-u':
                delete(sys.argv[2], uid=sys.argv[4])
            else:
                print_err()
        else:
            print_err()
    elif len(sys.argv) == 7:
        if sys.argv[1] == 'delete':
            if sys.argv[3] == '-c' and sys.argv[5] == '-u':
                delete(sys.argv[2], code=sys.argv[4], uid=sys.argv[6])
            elif sys.argv[5] == '-c' and sys.argv[3] == '-u':
                delete(sys.argv[2], code=sys.argv[6], uid=sys.argv[4])
            else:
                print_err()
        else:
            print_err()
    else:
        print_err()
