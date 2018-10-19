#!/usr/bin/env python3
import os, binascii, hashlib, base58, ecdsa
import random
import struct
import socket
import time
from hexdump import hexdump
from data import Data

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

def sign(sk, s256):
  while 1:
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der)
    N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    r, s = ecdsa.util.sigdecode_der(sig, sk.curve.generator.order())
    if s < N/2:
      break
  return sig

def compress_publ_key(publ_key):
  x = int(shex(publ_key[1:0x21]), 16)
  y = int(shex(publ_key[0x21:]), 16)
  if y & 1:
    return b'\x03' + binascii.unhexlify(format(x, '064x'))
  else:
    return b'\x02' + binascii.unhexlify(format(x, '064x'))

def uncompress_publ_key(publ_key):
  p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  x = int(shex(publ_key[1:0x21]), 16)
  y_square = (pow(x, 3, p) + 7) % p
  y_square_square_root = pow(y_square, (p+1)//4, p)
  if (publ_key[0] == 2 and y_square_square_root & 1) or (publ_key[0] == 3 and not y_square_square_root & 1):
    y = (-y_square_square_root) % p
  else:
    y = y_square_square_root
  ret = b"\x04" + binascii.unhexlify(format(x, '064x') + format(y, '064x'))
  return ret

def varstr(x):
  assert len(x) < 0xfd
  return bytes([len(x)]) + x

PRIV_KEY = open("seekrit", "rb").read()
#_, _, _, _, addr = priv_key_to_public(PRIV_KEY)
#print(addr)
#make_qrcode(addr)

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
  priv_key, WIF, publ_key, h1601, publ_addr = priv_key_to_public(PRIV_KEY)
  print(shex(publ_key))
  assert uncompress_publ_key(compress_publ_key(publ_key)) == publ_key

  # public address
  publ_addr2 = "1Lg2KRDk6CWfy1K6vi7rVqtBYMYdBZvXu4"
  tmp = base58.b58decode(publ_addr2)
  assert checksum(tmp[0:-4]) == tmp[-4:]
  h1602 = tmp[1:-4]

  scriptPubkey_sent = b"\x76\xa9\x14" + binascii.unhexlify("c04a6320665b9a1677f98e060519cec9bccdc810") + b"\x88\xac"
  scriptPubkey_1601 = b"\x76\xa9\x14" + h1601 + b"\x88\xac"
  scriptPubkey = b"\x76\xa9\x14" + h1602 + b"\x88\xac"

  print("WE WILL SEND: %s -> %s" % (publ_addr, publ_addr2))
  print(shex(h1601))
  print(shex(scriptPubkey_sent))

  """
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

  # REPLACE WITH YOUR TX BLOCK
  TX_BLOCK = "00000000000000000007a70ff954a0892d9367612993a8220af6c27ac3dbccfc"

  # request data about block tx is in
  msg = makeMessage(b'getdata', struct.pack('<BL32s', 1, 2, binascii.unhexlify(TX_BLOCK)[::-1]))

  sock.send(msg)
  cmd = b""
  while not cmd.decode().startswith("block"):
    cmd, payload = recvMessage(sock)

  f = open("bcache", "wb")
  f.write(payload)
  f.close()
  """
  payload = open("bcache", "rb").read()

  # parse the block
  print(len(payload))
  p = Data(payload[4+32+32+4+4+4:])
  txn_count = p.get_varint()
  print("parsing %d txns" % txn_count)

  # parsing txns
  txn_num = 0
  while not p.done():
    st = p.ptr
    version = p.get('i')
    if version > 2:
      print(version)
      hexdump(p.consume(0x20))
    assert version <= 2

    tx_in_count = p.get_varint()
    assert tx_in_count > 0  # witness will fail here, plz no witness
    inputs = []
    for i in range(tx_in_count):
      previous_output = p.consume(36)
      slen = p.get_varint()
      script = p.consume(slen)
      sequence = p.get("I")
      inputs.append((previous_output, script, sequence))

    tx_out_count = p.get_varint()
    assert tx_out_count > 0
    outputs = []
    for i in range(tx_out_count):
      value = p.get("Q")
      slen = p.get_varint()
      script = p.consume(slen)
      outputs.append((value, script))
    lock_time = p.get("I")

    txn = p.dat[st:p.ptr]
    if h1601 in txn:
      print("HASH BE",shex(dbl256(txn)[::-1]))
      input_outpoint = inputs[0][0]
      input_script = inputs[0][1]
      input_sequence = inputs[0][2]
      for i,x in enumerate(outputs):
        value, script = x
        if h1601 in script:
          output_value = value
          output_script = script
          output_index = i
          break
      break

    #print(txn_num, version, tx_in_count, tx_out_count, lock_time)
    #txn_num += 1

  print("output value:", output_value)
  print("output index:", output_index)
  hexdump(output_script)
  hexdump(scriptPubkey_sent)

  print("P2PKH:" + shex(scriptPubkey))
  outpoint = dbl256(txn) + struct.pack("<L", output_index)
  hexdump(outpoint)

  def make_raw_tx(outpoint, scriptCode, output_value, scriptPubkey):
    nSequence = b"\xff\xff\xff\xff"
    nLockTime = b"\x00\x00\x00\x00"

    raw_tx = struct.pack("<L", 1)  # version

    # input count
    raw_tx += b"\x01"
    # input
    raw_tx += outpoint
    raw_tx += varstr(scriptCode)
    raw_tx += nSequence

    # output count
    raw_tx += b"\x01"
    # output
    raw_tx += struct.pack("<Q", output_value)
    raw_tx += varstr(scriptPubkey)

    # nLockTime
    raw_tx += nLockTime
    return raw_tx

  def fake_raw_tx(outpoint, scriptCode, input_value, output_value, scriptPubkey):
    nSequence = b"\xff\xff\xff\xff"
    nLockTime = b"\x00\x00\x00\x00"

    raw_tx = struct.pack("<L", 1)  # version

    # hashPrevouts (for all inputs)
    raw_tx += dbl256(outpoint)

    # hashSequence (for all inputs)
    raw_tx += dbl256(nSequence)

    # outpoint
    raw_tx += outpoint

    # scriptCode
    raw_tx += varstr(scriptCode)

    # value
    raw_tx += struct.pack("<Q", input_value)

    # nSequence
    raw_tx += nSequence

    # TODO: hashOutputs
    raw_tx += dbl256(struct.pack("<Q", output_value) + varstr(scriptPubkey))

    # nLockTime
    raw_tx += nLockTime

    # sighash type
    raw_tx += b"\x41\x00\x00\x00"
    return raw_tx

  # testing, validate existing sig
  """
  dat = Data(input_script)
  sig = dat.consume(dat.get_varint())
  cpubl_key = dat.consume(dat.get_varint())
  publ_key = uncompress_publ_key(cpubl_key)
  vk = ecdsa.VerifyingKey.from_string(publ_key[1:], curve=ecdsa.SECP256k1)

  print(shex(input_outpoint))
  print(hex(input_sequence))
  raw_tx = fake_raw_tx(input_outpoint, scriptPubkey_sent, output_value, output_script)
  hexdump(raw_tx)
  s256 = dbl256(raw_tx)
  print(shex(s256))
  vk.verify_digest(derSigToHexSig(sig[:-1]), s256)
  print("GOODO!!!")
  exit(0)
  """

  FEE = 500
  raw_tx = fake_raw_tx(outpoint, output_script, output_value, output_value-FEE, scriptPubkey)

  s256 = dbl256(raw_tx)
  sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
  vk = ecdsa.VerifyingKey.from_string(publ_key[1:], curve=ecdsa.SECP256k1)
  sig = sign(sk, s256)
  vk.verify_digest(derSigToHexSig(sig), s256)

  scriptSig = varstr(sig + b'\x41') + varstr(publ_key)
  hexdump(scriptSig)

  real_raw_tx = make_raw_tx(outpoint, scriptSig, output_value-FEE, scriptPubkey)
  print(shex(real_raw_tx))
  exit(0)

  sock.send(makeMessage(b'tx', real_raw_tx))
  while 1:
    cmd, payload = recvMessage(sock)

