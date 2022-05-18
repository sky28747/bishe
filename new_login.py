from socket import *
from zlib import crc32
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature.pss import MGF1

local_host = ('192.168.2.120', 1741)
remote_host = ('192.168.2.13', 1740)
udp_socket = socket(AF_INET, SOCK_DGRAM)
udp_socket.bind(local_host)
num1 = 0
num2 = b"\x00\x00\x00\x00"
handle = b""
login_session = b""
app_session = b""
user = b"sky123"
password = b"123"


def receive():
    global num2
    while True:
        buf = udp_socket.recv(1 << 10)
        if len(buf) > 36:
            num2 = buf[20:24]
            return buf


def send(data):
    global num1
    num1 += 1
    payload = b"\xc5\x6b\x40\x40\x00\x32\x00\x0d\x00\x05\x01\x78\x80\x00\x00\x00\x01\x81"
    payload += handle
    payload += num1.to_bytes(4, byteorder='little', signed=False)
    payload += num2
    payload += len(data).to_bytes(4, byteorder='little', signed=False)
    payload += crc32(data).to_bytes(4, byteorder='little', signed=False)
    payload += data
    udp_socket.sendto(payload, ("192.168.2.13", 1740))


def start_login():
    login_request = b"\xc5\x6b\x40\x40\x00\x32\x00\x0d\x00\x05\x01\x78\x80\x00\x00\x00" \
                    + b"\xc3\x00\x01\x01\x47\xa3\x56\xcf\x70\x65\x7a\x1b\x00\x40\x1f\x00" \
                    + b"\x06\x00\x00\x00"
    udp_socket.sendto(login_request, remote_host)
    buf = udp_socket.recv(1024)
    while len(buf) != 40: buf = udp_socket.recv(1 << 10)
    global handle
    handle = buf[30:32]


def check_target_ident():
    payload = b"\x55\xcd\x10\x00\x01\x00\x01\x00\x00\x00\x00\x00" \
              + b"\x10\x00\x00\x00\x00\x00\x00\x00\x01\x8c\x80\x00\x00\x10\x00\x00" \
              + b"\x16\x07\x1a\x10\x0e\x09\x01\x05"
    send(payload)
    receive()


def get_login_session():
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
    send(payload)
    global login_session
    login_session = receive()[60:64]
    print("login session: " + login_session.hex())


def login():
    payload = b"\x55\xcd\x10\x00\x01\x00\x02\x00" + login_session \
              + b"\x10\x00\x00\x00\x00\x00\x00\x00\x22\x84\x80\x00" \
              + b"\x02\x00\x00\x00\x25\x84\x80\x00\x01\x00\x00\x00"
    send(payload)
    pub_key = RSA.importKey(receive()[60:] + b"--")
    cipher = PKCS1_OAEP.new(key=pub_key, hashAlgo=SHA256, mgfunc=lambda x, y: MGF1(x, y, SHA256))
    nonce = list(receive()[36:68])
    text = [0] * 60
    for i in range(len(password)): text[i] = password[i]
    for i in range(32): text[i] ^= nonce[i]
    text = bytes(text)
    encryped_text = cipher.encrypt(text)
    payload = b"\x55\xcd\x10\x00\x01\x00\x02\x00" + login_session + b"\x24\x01\x00\x00\x00\x00" \
              + b"\x00\x00\x22\x84\x80\x00\x02\x00\x00\x00\x25\x84\x80\x00\x02\x00\x00\x00\x81\x01" \
              + b"\x90\x02\x10\x0a" + user.ljust(10, b'\x00') + b"\x11\x80\x82\x00" + encryped_text
    send(payload)
    receive()
    global app_session
    payload = b"\x55\xcd\x10\x00\x02\x00\x01\x00" + login_session + b"\x10\x00\x00\x00\x00\x00" \
              + b"\x00\x00\x01\x8c\x80\x00\x41\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x00"
    send(payload)
    app_session = receive()[64:68]
    print("app session: " + app_session.hex())


def start():
    payload = b"\x55\xcd\x10\x00\x02\x00\x10\x00" + login_session + b"\x0c\x00\x00\x00\x00\x00" \
              + b"\x00\x00\x81\x01\x88\x00\x11\x84\x80\x00" + app_session
    send(payload)


def stop():
    payload = b"\x55\xcd\x10\x00\x02\x00\x11\x00" + login_session + b"\x0c\x00\x00\x00\x00\x00" \
              + b"\x00\x00\x81\x01\x88\x00\x11\x84\x80\x00" + app_session
    send(payload)


if __name__ == '__main__':
    start_login()
    # check_target_ident()
    get_login_session()
    login()
    start()
    # stop()
