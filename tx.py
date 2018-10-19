#!/usr/bin/env python3
import os, binascii, hashlib, base58, ecdsa
import random
import struct
import socket
import time
from hexdump import hexdump


# **** helpers ****

def make_qrcode(publ_addr):
  import qrcode
  img = qrcode.make(publ_addr)
  img.save("newcoin.png")

def derSigToHexSig(s):
  s, junk = ecdsa.der.remove_sequence(s)
  assert(junk == b'')
  x, s = ecdsa.der.remove_integer(s)
  y, s = ecdsa.der.remove_integer(s)
  return binascii.unhexlify(('%064x%064x' % (x, y)))

def shex(x):
  return binascii.hexlify(x).decode()

def dbl256(x):
  return hashlib.sha256(hashlib.sha256(x).digest()).digest()

def sha256(x):
  return hashlib.sha256(x).digest()

def checksum(x):
  return dbl256(x)[:4]

def b58wchecksum(x):
  return base58.b58encode(x+checksum(x))

def ripemd160(x):
  d = hashlib.new('ripemd160')
  d.update(x)
  return d

# priv_key should just be 32 random bytes
def priv_key_to_public(priv_key):
  # priv_key -> WIF
  WIF = b58wchecksum(b"\x80" + priv_key)

  # get public key
  sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
  vk = sk.get_verifying_key()
  publ_key = b"\x04" + vk.to_string()
  hash160 = ripemd160(hashlib.sha256(publ_key).digest()).digest()
  publ_addr = b58wchecksum(b"\x00" + hash160)
  return priv_key, WIF, publ_key, hash160, publ_addr

PRIV_KEY = open("seekrit", "rb").read()
_, _, _, _, addr = priv_key_to_public(PRIV_KEY)
print(addr)
make_qrcode(addr)

# **** cashes ****

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
  if len(payload) > 0x100:
    print("%s %d" % (command, len(payload)))
  else:
    print(command)
    hexdump(payload)
  return command, payload

if __name__ == "__main__":
  priv_key, WIF, publ_key, h1601, publ_addr = get_key_w_seed(1337)
  #_, _, h1602, publ_addr2 = get_key_w_seed(1338)
  # bitcoincash:qrtuhdj5mdupd0lz0hdl67m6w7zj09tdlscvxnm8ga == 1Lg2KRDk6CWfy1K6vi7rVqtBYMYdBZvXu4


  # public address
  publ_addr2 = "1Lg2KRDk6CWfy1K6vi7rVqtBYMYdBZvXu4"
  tmp = base58.b58decode(publ_addr2)
  assert checksum(tmp[0:-4]) == tmp[-4:]
  h1602 = tmp[1:-4]

  print("WE WILL SEND: %s -> %s" % (publ_addr, publ_addr2))
  print(shex(h1601))

  peers = socket.gethostbyname_ex('seed.bitcoinabc.org')[2]
  random.seed(time.time())
  random.shuffle(peers)

  for peer in peers:
    try:
      print(peer)
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((peer, 8333))

      sock.send(getVersionMsg())
      cmd, payload = recvMessage(sock)
      break
    except ConnectionResetError:
      continue

  cmd, payload = recvMessage(sock)
  sock.send(makeMessage(b'verack', b''))
  #cmd, payload = recvMessage(sock)
  #cmd, payload = recvMessage(sock)
  #cmd, payload = recvMessage(sock)
  #cmd, payload = recvMessage(sock)
  #cmd, payload = recvMessage(sock)

  #genesis_block = binascii.unhexlify('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
  #msg = makeMessage(b'getblocks', struct.pack('<LB32s32s', 70014, 1, genesis_block, b"\x00"*32))

  #my_block = binascii.unhexlify('000000000000000001b9d2f1286800f49908901f6d2259d5c09f0ba7716a53b6')
  #my_block = binascii.unhexlify('000000000000000001c927311afbac4de2dab77e29cf1e47b259d2f87a7ccb0c')
  #my_block = binascii.unhexlify('000000000000000000d1494100edab34cad3560b27604873d9c9a11702c4ac5b')
  #my_block = binascii.unhexlify('000000000000000001de22647f93fdb3603c6fc072534a218e110302c2b19dc3')
  my_block = binascii.unhexlify('000000000000000001de22647f93fdb3603c6fc072534a218e110302c2b19dc3')
  msg = makeMessage(b'getdata', struct.pack('<BL32s', 1, 2, my_block[::-1]))

  sock.send(msg)
  cmd = b""
  while not cmd.decode().startswith("block"):
    cmd, payload = recvMessage(sock)
  idx = payload.find(h1601)
  print(idx)

  # HACKS!!!!
  txn = payload[idx-0xc8+0x22+1:idx+0x3c]
  #txn = payload[idx-0xc8:idx+0x3c-0x22]
  hexdump(txn)
  #exit(0)
  #print("SHOULD BE","fce48731fb3d03084f97d42977b407683ab6e72827d2b65113bb319b45928b88")
  #print("SHOULD BE","d8e454302280e5ed1a3a1e7e89fcc6b63ca46ec3988fd29148a84fe9a4ee0aae")
  print("SHOULD BE","ce004d3bb163df52be5fcf1eed6551d287f47cb4c1d6cc2849d8f12ce7e17521")
  print("ISISIS BE",shex(dbl256(txn)[::-1]))
  print(shex(txn))
  #exit(0)

  output_value = struct.unpack("<Q", payload[idx-4-8:idx-4])[0]
  output_script = payload[idx-3:idx+0x19-3]

  print("output value:", output_value)
  hexdump(output_script)

  """
  01 00 00 00
  01
  73 7A 51 1B 50 12 61 77 06 DA 08 52 A0 18 98 36
  5F E6 7B 36 75 1E 52 05 43 67 72 22 EE EA A9 25
  32 00 00 00 <-- outpoint
  
  6A 47 30 44 02 20 01
  DA 0C 13 F8 57 95 45 BD  B0 35 62 DE A0 C1 45 4F  ....W.E..5b...EO
  61 71 A7 0A 48 0F DF FD  E8 56 7F 4F 97 0A 29 02  aq..H....V.O..).
  20 3B 8A D5 8F 87 19 83  F8 26 ED AA 6E 54 46 BE   ;.......&..nTF.
  AC E5 D8 8C 9B F9 3A A6  85 E3 5A 8F C5 6E B1 7A  ......:...Z..n.z
  8B 41

  21
  03 8E 36 9A 1F EB 36 7C 7F 72 AA B9 DF 0A 2B 9D 8B 1D D5 3A 07 35 90 EA 83 80 95 30 22 7B A1 66 C4

  FF FF FF FF
  02
  44 0A 02 00 00 00 00 00
  19 76 A9 14 E2 17 22 62 EA E7 88 09 50 01 2C B2 8A 5E 98 C1 F8 5D 44  AE 88 AC
  31 02 00 00 00 00 00 00
  19 76 A9 14 CD B2 39 FC E9 22 15 C4 E7 FF E7 A2 63 AA DE 9B 5F 97 E8 8C 88 AC
  00 00 00 00     
  """

  def varstr(x):
    assert len(x) < 0xfd
    return bytes([len(x)]) + x

  def make_raw_tx(txn, output_script, output_value, h1602):
    print("making raw tx with len: %x" % len(output_script))
    raw_tx = struct.pack("<L", 1)  # version

    # input
    raw_tx += b"\x01"
    raw_tx += dbl256(txn) + struct.pack("<L", 0)   # outpoint
    raw_tx += varstr(output_script)
    raw_tx += b"\xff\xff\xff\xff"

    # output
    raw_tx += b"\x01"
    raw_tx += struct.pack("<Q", output_value)
    raw_tx += varstr(b"\x76\xa9\x14" + h1602 + b"\x88\xac")

    # nLockTime
    raw_tx += b"\x00\x00\x00\x00"
    return raw_tx

  def fake_raw_tx(txn, output_script, output_value, h1602):
    raw_tx = struct.pack("<L", 1)  # version

    prevout = dbl256(txn) + struct.pack("<L", 0)   # outpoint
    nSequence = b"\xff\xff\xff\xff"
    scriptPubkey = varstr(b"\x76\xa9\x14" + h1602 + b"\x88\xac")

    # TODO: hashPrevouts
    raw_tx += dbl256(prevout)

    # TODO: hashSequence
    raw_tx += dbl256(nSequence)

    # outpoint
    raw_tx += prevout

    # scriptCode
    raw_tx += varstr(output_script)

    # value
    raw_tx += struct.pack("<Q", output_value)

    # nSequence
    raw_tx += nSequence

    # TODO: hashOutputs
    raw_tx += dbl256(struct.pack("<Q", output_value) + scriptPubkey)

    # nLockTime
    raw_tx += b"\x00\x00\x00\x00"

    # sighash type
    raw_tx += b"\x41\x00\x00\x00"
    return raw_tx

  FEE = 500
  raw_tx = fake_raw_tx(txn, output_script, output_value-FEE, h1602)
  hexdump(raw_tx)
  print(shex(raw_tx))
  print(shex(h1601))
  hexdump(output_script)

  s256 = dbl256(raw_tx)
  sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
  # 0x40 = SIGHASH_FORKID + 0x1 = SIGHASH_ALL
  while 1:
    print("signing")
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der)
    vk = ecdsa.VerifyingKey.from_string(publ_key[1:], curve=ecdsa.SECP256k1)
    assert(vk.verify_digest(derSigToHexSig(sig), s256))
    N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    r, s = ecdsa.util.sigdecode_der(sig, sk.curve.generator.order())
    if s < N/2:
      break

  hexdump(sig)
  scriptSig = varstr(sig + b'\x41') + varstr(publ_key)
  real_raw_tx = make_raw_tx(txn, scriptSig, output_value-FEE, h1602)

  hexdump(real_raw_tx)
  print(shex(real_raw_tx))
  #exit(0)

  sock.send(makeMessage(b'tx', real_raw_tx))
  while 1:
    cmd, payload = recvMessage(sock)

