import sys


def unlock(path, code, uid=-1):
    with open('/proc/2fa/path', 'w') as f:
        f.write(path)
    with open('/proc/2fa/code', 'w') as f:
        f.write(code)
    with open('/proc/2fa/uid', 'w') as f:
        f.write(uid)
    with open('/proc/2fa/state', 'w') as f:
        try:
            f.write("0")
        except:
            print('can not unlock ' + path + '.')


if __name__ == "__main__":
    if len(sys.argv) == 3:
        unlock(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 4:
        unlock(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("error: wrong args number.")
        print("usage: python " + sys.argv[0] +
              "COMMAND file_path 2fa_code [uid]")
