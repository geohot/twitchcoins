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
  return priv_key, WIF, hash160, publ_addr

# bitcoin cash magic
MAGIC_CASH = 0xe8f3e1e3

def makeMessage(command, payload):
  return struct.pack('<L12sL4s', MAGIC_CASH, command, len(payload), checksum(payload)) + payload

def getVersionMsg():
  version = 180002
  services = 1
  timestamp = int(time.time())
  addr_me = b"\x00"*26
  addr_you = b"\x00"*26
  nonce = random.getrandbits(64)
  sub_version_num = b"\x00"
  start_height = 0

  payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me,
      addr_you, nonce, sub_version_num, start_height)
  return makeMessage(b'version', payload)

def getTxMsg(tx_in, tx_out):
  version = 1
  locktime = 0
  payload = struct.pack('<LB', version, 1) + tx_in + b'\x01' + tx_out + struct.pack('<L', locktime) 
  return makeMessage(b'tx', payload)

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
  if len(payload) > 0x10:
    print("%s %d" % (command, len(payload)))
  else:
    print(command)
    hexdump(payload)
  return command, payload

if __name__ == "__main__":
  priv_key, WIF, h1601, publ_addr = get_key_w_seed(1337)
  _, _, h1602, publ_addr2 = get_key_w_seed(1338)
  print("WE WILL SEND: %s -> %s" % (publ_addr, publ_addr2))
  print(shex(h1601))

  peers = socket.gethostbyname_ex('seed.bitcoinabc.org')[2]
  peer = random.choice(peers)
  print(peer)

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((peer, 8333))

  sock.send(getVersionMsg())
  cmd, payload = recvMessage(sock)
  cmd, payload = recvMessage(sock)
  sock.send(makeMessage(b'verack', b''))
  cmd, payload = recvMessage(sock)
  cmd, payload = recvMessage(sock)
  cmd, payload = recvMessage(sock)
  cmd, payload = recvMessage(sock)
  cmd, payload = recvMessage(sock)

  #genesis_block = binascii.unhexlify('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
  #msg = makeMessage(b'getblocks', struct.pack('<LB32s32s', 70014, 1, genesis_block, b"\x00"*32))

  my_block = binascii.unhexlify('000000000000000001b9d2f1286800f49908901f6d2259d5c09f0ba7716a53b6')
  msg = makeMessage(b'getdata', struct.pack('<BL32s', 1, 2, my_block[::-1]))

  sock.send(msg)
  cmd, payload = recvMessage(sock)
  idx = payload.find(h1601)
  print(idx)
  hexdump(payload[idx-0xc8:idx+0x100])
  output_value = struct.unpack("<Q", payload[idx-3-8:idx-3])[0]
  output_script = payload[idx-3:idx+0x19-3]

  print(output_value)
  hexdump(output_script)


  exit(0)

  txes = payload[4+32+32+4+4+4:]
  #ptr = 3
  #for i in range(0x27d):
  #hexdump(txes[0:0x100])

  #idx = payload.find(binascii.unhexlify('8b0dd64c5cab786be66669545032ab20295c64da1b302dda224d4bb742fd0c53')[::-1])
  #print(idx)

  #exit(0)

  # question, how do I query the address
  print("will query %s" % publ_addr)

  """
  01000000
  01
  tx_in:
  8b0dd64c5cab786be66669545032ab20295c64da1b302dda224d4bb742fd0c53
  01000000
  19
  76a914010966776006953d5567439e5e39f86a0d273bee88ac
  ffffffff

  01
  tx_out:
  605af40500000000
  19
  76a914097072524438d003d23a2f23edb65aae1bb3e46988ac

  00000000
  01000000
  """

  raw_tx = struct.pack("<L", 1)  # version
  raw_tx += b"\x01"
  raw_tx += binascii.unhexlify("8b0dd64c5cab786be66669545032ab20295c64da1b302dda224d4bb742fd0c53")
  raw_tx += struct.pack("<L", 1)  # output index



  """


  txmsg = getTxMsg(b'', b'')
  hexdump(txmsg)
  exit(0)
  """

  #sock.send(getVersionMsg())
  # f9beb4d9676574626c6f636b73000000450000008634d5ae0100000001
  # 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
  # 0000000000000000000000000000000000000000000000000000000000000000
  #msg = makeMessage(b'getheaders', struct.pack('<LB32s32s', 70014, 1, genesis_block, b"\x00"*32))
  print("sent verack")

  #hexdump(sock.recv(1024))


  #sock.send(getVersionMsg())
  #cmd, payload = recvMessage(sock)



