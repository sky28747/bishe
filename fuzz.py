import socket
import sys
from types import *
import struct
import time
import logging
import random
from zlib import crc32

local_host = ('192.168.2.120', 1741)
remote_host = ('192.168.2.13', 1740)
TANGO_DOWN = ''
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dumbflagset = 0
logging.basicConfig(filename='./fuzzer.log', filemode='a', level=logging.DEBUG,
                    format='[%(asctime)s][%(levelname)s] %(message)s')
ratio = 30  # ratio%
num1 = 0
num2 = b"\x00\x00\x00\x00"
handle = b""
login_session = b""
app_session = b""


def magic(): return random.uniform(1, 100) <= ratio


def receive():
    global num2
    while True:
        buf = sock.recv(1 << 10)
        if len(buf) == 28:
            logging.info("error and restart")
            print("restart!!")
            create_connection()
        if len(buf) > 36:
            num2 = buf[20:24]
            return buf


# send login request and init value
def init():
    global num1, num2, handle, login_session, app_session
    num1 = 0
    num2 = b"\x00\x00\x00\x00"
    login_session = b""
    login_request = b"\xc5\x6b\x40\x40\x00\x32\x00\x0d\x00\x05\x01\x78\x80\x00\x00\x00" \
                    + b"\xc3\x00\x01\x01\x47\xa3\x56\xcf\x70\x65\x7a\x1b\x00\x40\x1f\x00" \
                    + b"\x06\x00\x00\x00"
    sock.sendto(login_request, remote_host)
    try:
        buf = sock.recv(1024)
        while len(buf) != 40: buf = sock.recv(1 << 10)
        handle = buf[30:32]
    except:
        print("crash!!")
        exit(0)


def create_connection():
    global sock
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)
    try:
        sock.settimeout(0.5)
        sock.bind(local_host)  # UDP
    except socket.error as msg:
        logging.exception("Connection Failed!")
    else:
        logging.info("Connected to Server: {}".format(remote_host))
    init()


def change(data):
    data = list(data)
    for i in range(len(data)):
        if magic() and magic() and magic():
            data[i] = random.randint(0, 255)
    data += bytes([random.randint(0, 255) for _ in range(random.randint(1, 1 << 10))])
    return bytes(data)


def packet(data):
    global num1
    num1 += 1
    if magic():
        tmp = change(data)
        if tmp != data:
            print("changed!!")
            data = tmp
    new_data = b"\xc5\x6b\x40\x40\x00\x32\x00\x0d\x00\x05\x01\x78\x80\x00\x00\x00\x01\x81"
    new_data += handle
    new_data += num1.to_bytes(4, byteorder='little', signed=False)
    new_data += num2
    new_data += len(data).to_bytes(4, byteorder='little', signed=False)
    new_data += crc32(data).to_bytes(4, byteorder='little', signed=False)
    new_data += data
    logging.debug("Sent Packet: %s" % hexstr(new_data))
    return new_data


def hexstr(s):
    return '-'.join('%02x' % c for c in s)


def check_target_ident():
    print("check_target_ident")
    payload = b"\x55\xcd\x10\x00\x01\x00\x01\x00\x00\x00\x00\x00" \
              + b"\x10\x00\x00\x00\x00\x00\x00\x00\x01\x8c\x80\x00\x00\x10\x00\x00" \
              + b"\x16\x07\x1a\x10\x0e\x09\x01\x05"
    payload = packet(payload)
    sock.sendto(payload, remote_host)
    receive()


def get_login_session():
    print("get_login_session")
    payload = b"\x55\xcd\x10\x00\x01\x00\x0a\x00\x11\x00\x00\x00\x90\x00\x00\x00\x00" \
              + b"\x00\x00\x00\x83\x01\x84\x01\x40\x84\x80\x00\x50\x51\xde\xc0\x41\xa0" \
              + b"\x80\x00\x4d\x61\x63\x68\x69\x6e\x65\x20\x45\x78\x70\x65\x72\x74\x20" \
              + b"\x4c\x6f\x67\x69\x63\x20\x42\x75\x69\x6c\x64\x65\x72\x00\x00\x00\x00" \
              + b"\x42\x9c\x80\x00\x43\x4f\x44\x45\x53\x59\x53\x20\x44\x65\x76\x65\x6c" \
              + b"\x6f\x70\x6d\x65\x6e\x74\x20\x47\x6d\x62\x48\x00\x00\x00\x00\x44\x8c" \
              + b"\x80\x00\x56\x32\x30\x2e\x30\x2e\x32\x31\x2e\x30\x00\x00\x43\x94\x80" \
              + b"\x00\x44\x45\x53\x4b\x54\x4f\x50\x2d\x30\x42\x44\x34\x4b\x34\x46\x2e" \
              + b"\x00\x00\x00\x00\x45\x8c\x80\x00\x33\x2e\x35\x2e\x31\x36\x2e\x34\x30" \
              + b"\x00\x00\x00\x46\x84\x80\x00\x03\x00\x00\x00"
    payload = packet(payload)
    sock.sendto(payload, remote_host)
    global login_session
    login_session = receive()[60:64]
    print("login session: " + login_session.hex())


def get_pubkey_and_nonce():
    print("get_pubkey_and_nonce")
    if len(login_session) == 0: return
    payload = b"\x55\xcd\x10\x00\x01\x00\x02\x00" + login_session \
              + b"\x10\x00\x00\x00\x00\x00\x00\x00\x22\x84\x80\x00" \
              + b"\x02\x00\x00\x00\x25\x84\x80\x00\x01\x00\x00\x00"
    payload = packet(payload)
    sock.sendto(payload, remote_host)
    receive()
    receive()


def vuln():
    payload = [random.randint(0, 255) for _ in range(random.randint(1, 1 << 10))]
    payload = bytes(payload)
    sock.sendto(payload, remote_host)
    receive()


def fuzz():
    create_connection()
    func_list = [get_login_session, get_pubkey_and_nonce, check_target_ident]
    while True:
        try:
            random.choice(func_list)()
        except:
            continue


if __name__ == '__main__':
    fuzz()
