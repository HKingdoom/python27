#! /usr/bin/python

import socket
import serial
import struct
import time
from codec_cq import *


class Reader24G_Exception(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class Reader24G(object):

    def __init__(self):
        self.frameCoder = EtcCodec()
        self.mode = 0

    def open(self, mode, ipaddr, port):
        self.mode = mode
        if self.mode == 0:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(2)
            self.sock.connect((ipaddr, port))
        else:
            self.port = serial.Serial(
                port=port, baudrate=38400, parity='N', bytesize=8, stopbits=1, timeout=10)

    def close(self):
        if self.mode == 0:
            self.sock.close()
        else:
            self.port.close()

    def send_frame(self, frame):
        encodedFrame = self.frameCoder.encode(frame)
        if self.mode == 0:
            self.sock.send(encodedFrame)
        else:
            self.port.write(encodedFrame)

    def recv_frame(self):
        decodedFrame = ''
        if self.mode == 0:
            response = self.sock.recv(10240)
            decodedFrame = self.frameCoder.decode(response)
        else:
            while not decodedFrame:
                response = self.port.read()
                if not response:
                    self.port.close()
                    raise Reader24G_Exception("timeout")
                decodedFrame = self.frameCoder.decode(response)
        return decodedFrame

    def queryVersion(self):
        self.send_frame('\x0a')
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x0a':
            raise Reader24G_Exception("queryVersion fail!")
        return binascii.hexlify(decodedFrame[1:])

    def querySlaveInfo(self, slave_num):
        self.send_frame('\x0b' + chr(slave_num))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x0b':
            raise Reader24G_Exception("querySlaveInfo fail!")
        return binascii.hexlify(decodedFrame[1:])

    def setDeviceIp(self, ip, netmask, gateway):
        ipbin = binascii.unhexlify(ip)
        nemsakbin = binascii.unhexlify(netmask)
        gatewaybin = binascii.unhexlify(gateway)
        self.send_frame('\x0c' + ipbin + nemsakbin + gatewaybin)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x0c':
            raise Reader24G_Exception("setDeviceIp fail!")
        return

    def setDeviceSn(self, sn):
        snbin = binascii.unhexlify(sn)
        if len(snbin) != 10:
            raise Reader24G_Exception("device sn length not correct!")
        self.send_frame('\x0d' + snbin)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x0d':
            raise Reader24G_Exception("setDeviceSn fail!")
        return

    def downloadVersion(self):
        pass

    def queryTagInfo(self, flag):
        self.send_frame('\x0f' + chr(flag))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x0f':
            raise Reader24G_Exception("queryTagInfo fail!")
        return binascii.hexlify(decodedFrame[1:])

    def setSlaveDirection(self, addr, direction):
        self.send_frame('\x10' + chr(addr) + chr(direction))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x10':
            raise Reader24G_Exception("setSlaveDirection fail!")
        return

    def setSlaveAddr(self, oldAddr, newAddr):
        self.send_frame('\x11' + chr(oldAddr) + chr(newAddr))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x11':
            raise Reader24G_Exception("setSlaveAddr fail!")

    def setSlaveDatt(self, addr, datt):
        self.send_frame("\x12" + chr(addr) + chr(datt))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x12':
            raise Reader24G_Exception("setSlaveDatt fail!")

    def setSlaveRssi(self, addr, rssi):
        self.send_frame("\x13" + chr(addr) + chr(rssi))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x13':
            raise Reader24G_Exception("setSlaveRssi fail!")

    def setSlaveFreq(self, addr, freq):
        self.send_frame("\x14" + chr(addr) + chr(freq))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x14':
            raise Reader24G_Exception("setSlaveFreq fail!")

    def setRtc(self, timeStr):
        #timebin = binascii.hexlify(time)
        self.send_frame("\x15" + timeStr)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x15':
            raise Reader24G_Exception("setRtc fail!")

    def readRtc(self):
        self.send_frame("\x16")
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x16':
            raise Reader24G_Exception("readRtc fail!")
        return binascii.hexlify(decodedFrame[1:8])

    def readDeviceSn(self):
        self.send_frame("\x17")
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x17':
            raise Reader24G_Exception("readDeviceSn fail!")
        return binascii.hexlify(decodedFrame[1:11])

    def setServerIp(self, addr, port):
        addrStr = binascii.unhexlify(addr)
        portStr = struct.pack("!H", port)
        self.send_frame("\x18" + addrStr + portStr)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x18':
            self.close()
            raise Reader24G_Exception("setServerIp fail!")

    def downloadVersion(self, flag, offset, data):
        offs = struct.pack("!I", offset)
        lens = struct.pack("!H", len(data))
        self.send_frame("\x0e" + chr(flag) + offs + lens + data)
        decodedFrame = self.recv_frame()
        print "donwload version receive a frame"
        print repr(decodedFrame)
        if decodedFrame[0] != '\x0e' or decodedFrame[1] != '\x00':
            self.close()
            raise Reader24G_Exception("downloadVersion fail!")

    def resetReader(self):
        self.send_frame('\x1b')
        return
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x1b':
            self.close()
            raise Reader24G_Exception("resetReader fail!")

    def queryIpAddress(self):
        self.send_frame('\x1c')
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x1c':
            self.close()
            raise Reader24G_Exception("queryIpAddress fail!")
        return binascii.hexlify(decodedFrame[1:])

    def setJudgeInterval(self, interval):
        interval_bin = struct.pack("!I", interval)
        self.send_frame('\x19' + interval_bin)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x19':
            self.close()
            raise Reader24G_Exception("setJudgeInterval fail!")

    def setCommLink(self, commlink):
        self.send_frame('\x1d' + chr(commlink))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x1d':
            self.close()
            raise Reader24G_Exception("setCommLink fail!")

    def queryTagLog(self, query_date, query_flag, query_index):
        self.send_frame('\x1e' + chr(query_date) + chr(query_flag) + struct.pack("!H", query_index))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x1e':
            self.close()
            raise Reader24G_Exception("send_frame fail!")
        return decodedFrame[1:]

    def queryMasterConfig(self):
        self.send_frame('\x1f')
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x1f':
            self.close()
            raise Reader24G_Exception("queryMasterConfig fail!")
        return decodedFrame[1:]

    def testNandFlash(self):
        self.send_frame('\x20')
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x20':
            self.close()
            raise Reader24G_Exception("testNandFlash fail!")
        return

    def setMacAddr(self, mac_addr):
        self.send_frame('\x21' + mac_addr)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x21':
            self.close()
            raise Reader24G_Exception("setMacAddr fail!")
        return


    def readMacAddr(self):
        self.send_frame('\x22')
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x22':
            self.close()
            raise Reader24G_Exception("readMacAddr fail!")
        return decodedFrame[1:]

    def queryServerIp(self):
        self.send_frame('\x23')
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x23':
            self.close()
            raise Reader24G_Exception("queryServerIp fail!")
        return decodedFrame[1:]

    def readEeprom(self, offset, length):
        self.send_frame('\x24' + chr(offset) + chr(length))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x24':
            self.close()
            raise Reader24G_Exception("readEeprom fail!")
        return decodedFrame[1:]

    def writeEeprom(self, offset, length, data):
        self.send_frame('\x25' + chr(offset) + chr(length) + data)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x25':
            self.close()
            raise Reader24G_Exception("writeEeprom fail!")
        return 

    def startMonitor(self):
        local_ip_str = socket.gethostbyname(socket.getfqdn())
        local_ip = socket.inet_aton(local_ip_str)
        self.send_frame('\x26' + local_ip)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x26':            
            self.close()
            raise Reader24G_Exception("startMonitor fail!")
        return 

    def stopMonitor(self):
        self.send_frame('\x27')
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x27':
            self.close()
            raise Reader24G_Exception("stopMonitor fail!")
        return

    def testSendPower(self, targetAddr, plateAddr, level):
        self.send_frame('\x28' + chr(plateAddr) + chr(targetAddr) + chr(level))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x28':
            self.close()
            raise Reader24G_Exception("testSendPower fail!")
        return ord(decodedFrame[2])

    def enterRecvSensi(self, targetAddr, plateAddr):
        self.send_frame('\x29' + chr(plateAddr) + chr(targetAddr) + chr(1))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x29':
            self.close()
            raise Reader24G_Exception("enterRecvSensi fail!")
        return

    def getRecvSensiResult(self, targetAddr, plateAddr):
        self.send_frame('\x29' + chr(plateAddr) + chr(targetAddr) + chr(0))
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x29':
            self.close()
            raise Reader24G_Exception("getRecvSensiResult fail!")
        return ord(decodedFrame[2])*256 + ord(decodedFrame[3])

    def setAppDeviceId(self, appId):
        snbin = binascii.unhexlify(appId)
        if len(snbin) != 10:
            raise Reader24G_Exception("device sn length not correct!")
        self.send_frame('\x2a' + snbin)
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x2a':
            raise Reader24G_Exception("setAppDeviceId fail!")
        return

    def readAppDeviceId(self):
        self.send_frame("\x2b")
        decodedFrame = self.recv_frame()
        if decodedFrame[0] != '\x2b':
            raise Reader24G_Exception("readAppDeviceId fail!")
        return binascii.hexlify(decodedFrame[1:11])

    







if __name__ == '__main__':
    reader = Reader24G()

    '''
    reader.open(0, "192.168.0.10", 3010)
    version = reader.queryVersion()
    print repr(version)
    slaveInfo = reader.querySlaveInfo()
    print repr(slaveInfo)
    reader.setDeviceIp("C0A8000A")
    reader.setDeviceSn("010203040506")
    tagInfo = reader.queryTagInfo()
    print tagInfo
    reader.setSlaveDirection(1)
    reader.close()
    '''

    reader.open(0, "192.168.0.10", 5000)
    reader.setSlaveFreq(1, 29)
    #reader.setMacAddr('0x02\x00\x00\x00\x00\x00')


    reader.close()
