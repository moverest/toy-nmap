#!/usr/bin/env python3
import socket
import sys

def send_ftp_command(s, cmd):
        s.sendall(cmd + b'\r\n')
        return read_ftp_response(s)

def read_ftp_response(s):
        response = s.recv(1024).decode("utf-8")
        code, msg = response.split(" ", 1)
        return int(code), msg

def make_ftp_socket(host, port):
    s =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    code, msg = read_ftp_response(s)
    if code != 220:
        raise Exception("Connexion error: %d %s" % (code, msg))

    code, msg = send_ftp_command(s, b'USER anonymous')
    if code != 331:
        raise Exception("Auth failure (username): %d %s" % (code, msg))

    code, _ = send_ftp_command(s, b'PASS anonymous')
    if code != 230:
        raise Exception("Auth failure (password)")

    return s

def is_port_open(s, host, port):
    port = list(map(str, [port // 0x100, port % 0x100]))
    host = host.split(".")

    cmd = b"PORT " + ",".join(host + port).encode("utf-8")
    code, msg = send_ftp_command(s, cmd)

    return code == 200

def main(ftp_host, ftp_port, host, ports):
    s = make_ftp_socket(ftp_host, ftp_port)
    for port in ports:
        sys.stdout.write(str(port))
        sys.stdout.flush()

        if (is_port_open(s, host, port)):
            sys.stdout.write(" \x1b[32mopen\x1b[0m\n")
        else:
            sys.stdout.write("\x1b[1K\r")

if __name__ == '__main__':
    ftp_host = sys.argv[1]
    ftp_port = int(sys.argv[2])
    host = sys.argv[3]
    min_port = int(sys.argv[4])
    max_port = min_port

    if len(sys.argv) == 6:
        max_port = int(sys.argv[5])

    main(ftp_host, ftp_port, host, range(min_port, max_port+1))
