#coding=utf8
import binascii

class CodecState(object):
    def __init__(self, codec):
        self.codec = codec

class CodecStateInit(CodecState):        
    def next(self, ch):
        #print "CodecStateInit next is called ch is " + binascii.hexlify(ch)
        self.codec.recv_buf = []
        if ch == '\x55':
            self.codec.state = CodecStateAA(self.codec)
        return ""

class CodecStateAA(CodecState):
    def next(self, ch):
        #print "CodecStateAA next is called ch is "+ binascii.hexlify(ch)
        if ch == '\xAA':
            self.codec.state = CodecStateRSCTL(self.codec)
        else:
            self.codec.state = CodecStateInit(self.codec)
        return ""

class CodecStateRSCTL(CodecState):
    def next(self, ch):
        #print "CodecStateRSCTL next is called ch is "+binascii.hexlify(ch)
        self.codec.RSCTL = ch
        self.codec.state = CodecStateLenHigh(self.codec)
        return ""

class CodecStateLenHigh(CodecState):
    def next(self, ch):
        self.codec.frame_len = ord(ch)*256
        self.codec.state = CodecStateLenLow(self.codec)
        return ""

class CodecStateLenLow(CodecState):
    def next(self, ch):
        #print "CodecStateLenLow next is called ch is "+binascii.hexlify(ch)
        #print "frame len is %d " % ord(ch)
        self.codec.frame_len += ord(ch)
        self.codec.state = CodecStateData(self.codec)
        return ""


class CodecStateData(CodecState):
    def next(self, ch):
        #print "CodecStateData next is called ch is "+binascii.hexlify(ch)
        self.codec.recv_buf.append(ch)        
        if self.codec.frame_len == len(self.codec.recv_buf):
            self.codec.state = CodecStateBCC(self.codec)

def calc_bcc(source, init=0):
    bcc = init;
    for x in source:
        bcc ^= x
    return bcc

class CodecStateBCC(CodecState):
    def next(self, ch):
        #print "CodecStateBCC next is called ch is "+binascii.hexlify(ch)
        #print "decode frame is ", binascii.hexlify(bytearray(self.codec.recv_buf))
        self.codec.state = CodecStateInit(self.codec)
        bcc = ord(self.codec.RSCTL)
        return str(bytearray(self.codec.recv_buf))

class EtcCodec(object):
    def __init__(self):
        self.state = CodecStateInit(self)
        self.recv_buf = []
        self.RSCTL = '\x02'
        self.frame_len = 0
        self.frame_type = '\xb2'
        self.remain = ''
        
    def encode(self, source):
        encode_len = len(source)
        #rsctl = chr(((ord(self.RSCTL)>>4)|(ord(self.RSCTL)<<4))&0xff)
        #rsctl = chr((ord(self.RSCTL))%8)
        rsctl = self.RSCTL
        temp = ['\x55', '\xaa', rsctl, chr(encode_len/256), chr(encode_len%256)]
        bcc = ord(rsctl)
        bcc ^= encode_len/256
        bcc ^= encode_len%256
        for ch in source:
            bcc ^= ord(ch) 
            temp.append(ch)
        temp.append(chr(bcc))
        #print "encoded frame is ", binascii.hexlify(bytearray(temp))
        return str(bytearray(temp))

    def decode(self, source):
        ret = ""
        data = self.remain + source
        #print "etc codec decode is called
        for i in range(len(data)):
            decoded = self.state.next(data[i])
            if decoded:
                ret = decoded
                self.remain = data[i:]
                break
        return ret

    def close(self):
        self.state = CodecStateInit(self)
        self.RSCTL = '\x02'
        self.frame_len = 0
        
