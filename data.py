import struct

class Data(object):
  def __init__(self, dat):
    self.dat = dat
    self.ptr = 0
  
  def consume(self, cnt):
    self.ptr += cnt
    assert(self.ptr <= len(self.dat))
    return self.dat[self.ptr-cnt:self.ptr]

  def get(self, stype):
    tlen = struct.calcsize("<"+stype)
    return struct.unpack("<"+stype, self.consume(tlen))[0]

  def done(self):
    return self.ptr == len(self.dat)

  def get_varint(self):
    x = self.consume(1)[0]
    if x < 0xfd:
      return x
    elif x == 0xfd:
      return self.get('H')
    elif x == 0xfe:
      return self.get('I')
    elif x == 0xff:
      return self.get('Q')

