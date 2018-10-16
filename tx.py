#!/usr/bin/env python3
import os, binascii, hashlib, base58, ecdsa
import random

"""
import qrcode
img = qrcode.make(publ_addr)
img.save("coin.png")
"""

def shex(x):
  return binascii.hexlify(x).decode()

def b58wchecksum(x):
  checksum = hashlib.sha256(hashlib.sha256(x).digest()).digest()[:4]
  return base58.b58encode(x+checksum)

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

priv_key, WIF, publ_addr = get_key_w_seed(1337)
_, _, publ_addr2 = get_key_w_seed(1338)
print("%s -> %s" % (publ_addr, publ_addr2))


