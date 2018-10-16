#!/usr/bin/env python3
import os, binascii, hashlib, base58, ecdsa
import random
import struct
import socket
import time
from hexdump import hexdump

"""
import qrcode
img = qrcode.make(publ_addr)
img.save("coin.png")
"""

def shex(x):
  return binascii.hexlify(x).decode()


def checksum(x):
  return hashlib.sha256(hashlib.sha256(x).digest()).digest()[:4]

def b58wchecksum(x):
  return base58.b58encode(x+checksum(x))

def ripemd160(x):
  d = hashlib.new('ripemd160')
  d.update(x)
  return d

def get_key_w_seed(seed=1337):
  # generate private key
  random.seed(seed)
  priv_key = bytes([random.randint(0, 255) for x in range(32)])

  # priv_key -> WIF
  WIF = b58wchecksum(b"\x80" + priv_key)

  # get public key
  sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
  vk = sk.get_verifying_key()
  publ_key = b"\x04" + vk.to_string()
  hash160 = ripemd160(hashlib.sha256(publ_key).digest()).digest()
  publ_addr = b58wchecksum(b"\x00" + hash160)

  return priv_key, WIF, publ_addr

# bitcoin cash magic
MAGIC_CASH = 0xe8f3e1e3

def makeMessage(magic, command, payload):
  return struct.pack('<L12sL4s', magic, command, len(payload), checksum(payload)) + payload

def getVersionMsg():
  version = 170002
  services = 1
  timestamp = int(time.time())
  addr_me = b"\x00"*26
  addr_you = b"\x00"*26
  nonce = random.getrandbits(64)
  sub_version_num = b"\x00"
  start_height = 0

  payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me,
      addr_you, nonce, sub_version_num, start_height)
  return makeMessage(MAGIC_CASH, b'version', payload)

def sock_read(sock, count):
  ret = b''
  while len(ret) < count:
    ret += sock.recv(count-len(ret))
  return ret

def recvMessage(sock):
  magic, command, plen, cksum = struct.unpack('<L12sL4s', sock_read(sock, 24))
  assert magic == MAGIC_CASH
  payload = sock_read(sock, plen)
  assert checksum(payload) == cksum
  print(command)
  hexdump(payload)
  return command, payload

"""
priv_key, WIF, publ_addr = get_key_w_seed(1337)
_, _, publ_addr2 = get_key_w_seed(1338)
print("%s -> %s" % (publ_addr, publ_addr2))
"""

if __name__ == "__main__":
  peers = socket.gethostbyname_ex('seed.bitcoinabc.org')[2]
  peer = random.choice(peers)
  print(peer)

  vermsg = getVersionMsg()
  hexdump(vermsg)

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((peer, 8333))
  sock.send(vermsg)

  cmd, payload = recvMessage(sock)
  cmd, payload = recvMessage(sock)
  cmd, payload = recvMessage(sock)

