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

def dbl256(x):
  return hashlib.sha256(hashlib.sha256(x).digest()).digest()

def checksum(x):
  return dbl256(x)[:4]

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
  return priv_key, WIF, publ_key, hash160, publ_addr

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
  publ_addr2 = "1Lg2KRDk6CWfy1K6vi7rVqtBYMYdBZvXu4"
  tmp = base58.b58decode(publ_addr2)
  assert checksum(tmp[0:-4]) == tmp[-4:]
  h1602 = tmp[1:-4]

  print("WE WILL SEND: %s -> %s" % (publ_addr, publ_addr2))
  print(shex(h1601))

  peers = socket.gethostbyname_ex('seed.bitcoinabc.org')[2]
  random.seed(time.time())
  peer = random.choice(peers)
  #peer = "39.108.100.122"
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

  #my_block = binascii.unhexlify('000000000000000001b9d2f1286800f49908901f6d2259d5c09f0ba7716a53b6')
  my_block = binascii.unhexlify('000000000000000001c927311afbac4de2dab77e29cf1e47b259d2f87a7ccb0c')
  msg = makeMessage(b'getdata', struct.pack('<BL32s', 1, 2, my_block[::-1]))

  sock.send(msg)
  cmd, payload = recvMessage(sock)
  idx = payload.find(h1601)
  print(idx)

  # HACKS!!!!
  txn = payload[idx-0xc8+0x22:idx+0x3c]
  hexdump(txn)
  print("SHOULD BE","a692bf4900c3474d3d7cfc9f824cdfcaff7bd0f7914f8ed8f43f8ebf31f71420")
  print("SHOULD BE",shex(dbl256(txn)[::-1]))

  output_value = struct.unpack("<Q", payload[idx-4-8:idx-4])[0]
  output_script = payload[idx-3:idx+0x19-3]

  print(output_value)
  hexdump(output_script)

  """
  00000000: 02 74 78 10 47 6D 61 6E  64 61 74 6F 72 79 2D 73  .tx.Gmandatory-s
  00000010: 63 72 69 70 74 2D 76 65  72 69 66 79 2D 66 6C 61  cript-verify-fla
  00000020: 67 2D 66 61 69 6C 65 64  20 28 53 69 67 6E 61 74  g-failed (Signat
  00000030: 75 72 65 20 6D 75 73 74  20 75 73 65 20 53 49 47  ure must use SIG
  00000040: 48 41 53 48 5F 46 4F 52  4B 49 44 29 C1 DE EC 2A  HASH_FORKID)...*
  00000050: E0 0E 5D F3 1B 17 9E 57  9E 17 3B 01 6C 32 F9 F2  ..]....W..;.l2..
  00000060: DB 7E 54 E7 F4 C1 86 9D  22 15 8E D2              .~T....."...
  """

  """
  00000000: 02 74 78 10 61 6D 61 6E  64 61 74 6F 72 79 2D 73  .tx.amandatory-s
  00000010: 63 72 69 70 74 2D 76 65  72 69 66 79 2D 66 6C 61  cript-verify-fla
  00000020: 67 2D 66 61 69 6C 65 64  20 28 53 69 67 6E 61 74  g-failed (Signat
  00000030: 75 72 65 20 6D 75 73 74  20 62 65 20 7A 65 72 6F  ure must be zero
  00000040: 20 66 6F 72 20 66 61 69  6C 65 64 20 43 48 45 43   for failed CHEC
  00000050: 4B 28 4D 55 4C 54 49 29  53 49 47 20 6F 70 65 72  K(MULTI)SIG oper
  00000060: 61 74 69 6F 6E 29 8A 33  5B 75 59 9F 06 95 0B 51  ation).3[uY....Q
  00000070: 82 85 0D 26 D1 98 B3 CD  6C 7E 1B 86 10 F3 06 42  ...&....l~.....B
  00000080: 34 9E E9 74 15 F0                                 4..t..
  """

  def make_raw_tx(txn, output_script, output_value, h1602):
    print("making raw tx with len: %x" % len(output_script))
    raw_tx = struct.pack("<L", 1)  # version

    # input
    raw_tx += b"\x01"
    raw_tx += dbl256(txn) #[::-1]
    raw_tx += struct.pack("<L", 0)  # output index
    raw_tx += bytes([len(output_script)])
    raw_tx += output_script
    raw_tx += b"\xff\xff\xff\xff"

    # output
    raw_tx += b"\x01"
    raw_tx += struct.pack("<Q", output_value-243)
    raw_tx += b"\x19" + b"\x76\xa9\x14" + h1602 + b"\x88\xac"
    raw_tx += b"\x00\x00\x00\x00"
    return raw_tx

  def varstr(x):
    assert len(x) < 0xfd
    return bytes([len(x)]) + x

  raw_tx = make_raw_tx(txn, output_script, output_value, h1602) + b"\x41\x00\x00\x00"
  hexdump(raw_tx)

  sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
  # 0x40 = SIGHASH_FORKID + 0x1 = SIGHASH_ALL
  sig = sk.sign_digest(dbl256(raw_tx), sigencode=ecdsa.util.sigencode_der) + b"\x01" # 01 is hashtype
  scriptSig = varstr(sig) + varstr(publ_key)
  real_raw_tx = make_raw_tx(txn, scriptSig, output_value, h1602)
  hexdump(real_raw_tx)

  sock.send(makeMessage(b'tx', real_raw_tx))
  while 1:
    cmd, payload = recvMessage(sock)

  exit(0)

  #pubKey = keyUtils.privateKeyToPublicKey(privateKey)
  #scriptSig = utils.varstr(sig).encode('hex') + utils.varstr(pubKey.decode('hex')).encode('hex')
  #signed_txn = makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs)
  #verifyTxnSignature(signed_txn)
  #dbl256(raw_tx)

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



