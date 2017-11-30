import random
import time
import unittest
import binascii
import socket
from Reader24G import *

reader = Reader24G()

class MasterTestCase(unittest.TestCase):

    def setUp(self):
        reader.open(0, "192.168.0.10", 5000)

    def tearDown(self):
        reader.close()

    def test_Eeprom(self):
        for x in range(4):
            reader.writeEeprom(0*x, 32, "\x01\x02\x03\x04"*8)
            ret = reader.readEeprom(0*x, 32)
            self.assertEqual(ret, "\x01\x02\x03\x04"*8)

    def test_NandFlash(self):
        reader.testNandFlash()

    def test_Rtc(self):
        reader.setRtc("\x14\x10\x08\x1a\x0c\x0d\x0e")
        time.sleep(2)
        ret = reader.readRtc()
        self.assertEqual(ret, "1410081a0c0d10")

    def test_Rs485(self):
        reader.close()
        reader.open(1, '', 'COM4')
        ret = reader.queryServerIp()
        self.assertNotEqual(ret, None)
        reader.close()
        reader.open(0, "192.168.0.10", 5000)

    def test_SendPower(self):
        ret = reader.testSendPower(1, 2, 1)
        self.assertGreaterEqual(ret, 65)
        self.assertLessEqual(ret, 70)
        ret = reader.testSendPower(1, 2, 2)
        self.assertGreaterEqual(ret, 68)
        self.assertLessEqual(ret, 73)
        ret = reader.testSendPower(1, 2, 3)
        self.assertGreaterEqual(ret, 72)
        self.assertLessEqual(ret, 77)
        ret = reader.testSendPower(1, 2, 4)
        self.assertGreaterEqual(ret, 77)
        self.assertLessEqual(ret, 82)
        ret = reader.testSendPower(1, 2, 5)
        self.assertGreaterEqual(ret, 84)
        self.assertLessEqual(ret, 90)

    def test_RecvSensi(self):
        reader.enterRecvSensi(1, 2)
        time.sleep(7)
        ret = reader.getRecvSensiResult(1, 2)
        self.assertGreaterEqual(ret, 970)

    def test_SetDeviceSn(self):
        reader.setDeviceSn("32010203040506070809")
        ret = reader.readDeviceSn()
        self.assertEqual(ret, "32010203040506070809")

    def test_SetAppDeviceId(self):
        reader.setAppDeviceId("32010203040506070809")
        ret = reader.readAppDeviceId()
        self.assertEqual(ret, "32010203040506070809")


    def test_SetDeviceIp(self):
        ipAddrStr = binascii.hexlify(socket.inet_aton(str("192.168.0.10")))
        netMaskStr = binascii.hexlify(socket.inet_aton(str("255.255.255.0")))
        gatewayStr = binascii.hexlify(socket.inet_aton(str("192.168.0.1")))
        reader.setDeviceIp(ipAddrStr, netMaskStr, gatewayStr)
        device_ip = reader.queryIpAddress()
        addr = socket.inet_ntoa(binascii.unhexlify(device_ip[0:8]))
        netmask = socket.inet_ntoa(binascii.unhexlify(device_ip[8:16]))
        gateway = socket.inet_ntoa(binascii.unhexlify(device_ip[16:24]))
        self.assertEqual(addr, "192.168.0.10")
        self.assertEqual(netmask, "255.255.255.0")
        self.assertEqual(gateway, "192.168.0.1")


    def test_SetDeviceMac(self):
        mac_addr = binascii.unhexlify("020000000000")
        reader.setMacAddr(mac_addr)
        ret = reader.readMacAddr()
        self.assertEqual(ret, mac_addr)

    def test_SetServerIp(self):      
        serverAddrStr = binascii.hexlify(socket.inet_aton(str("192.168.0.200")))
        port = 5000
        reader.setServerIp(serverAddrStr, port)
        ret = reader.queryServerIp()
        addr = socket.inet_ntoa(ret[0:4])
        port = ord(ret[4])*256+ord(ret[5])
        self.assertEqual(addr, "192.168.0.200")
        self.assertEqual(port, 5000)

    def test_SetCommLink(self):
        reader.setCommLink(0)

    def test_SetJudgeInterval(self):
        reader.setJudgeInterval(30)

    def test_SetDatt(self):
        reader.setSlaveDatt(1, 0)

    def test_SetRssi(self):
        reader.setSlaveRssi(1, 95)

    def test_SetDirection(self):
        reader.setSlaveDirection(1, 1)

    def test_VerifySlaveConfig(self):
        ret = reader.querySlaveInfo(1)
        self.assertEqual(ret[0:12], "0201005f1d01")


    def test_VerifyMasterConfig(self):
        ret = reader.queryMasterConfig()
        ip_addr = socket.inet_ntoa(ret[0:4])
        net_mask =  socket.inet_ntoa(ret[4:8])
        gate_way =  socket.inet_ntoa(ret[8:12])
        server_ip =  socket.inet_ntoa(ret[12:16])
        (server_port, ) = struct.unpack("!H", ret[16:18])
        (judge_time, ) = struct.unpack("!I", ret[18:22])
        comm_link = ord(ret[22])
        version = ret[23:]
        self.assertEqual(ip_addr, "192.168.0.10")
        self.assertEqual(net_mask, "255.255.255.0")
        self.assertEqual(gate_way, "192.168.0.1")
        self.assertEqual(server_ip, "192.168.0.200")
        self.assertEqual(server_port, 5000)
        self.assertEqual(judge_time, 30)
        self.assertEqual(comm_link, 0)
        self.assertEqual(version[0:18], "READER_V01.10.01-A")



class SlaveTestCase(unittest.TestCase):

    def setUp(self):
        reader.open(0, "192.168.0.10", 5000)

    def tearDown(self):
        reader.close()

    def test_SetAddr(self):
        reader.setSlaveAddr(2, 2)

    def test_SetDirection(self):
        reader.setSlaveDirection(2, 0)

    def test_SendPower(self):
        ret = reader.testSendPower(2, 1, 1)
        self.assertGreaterEqual(ret, 65)
        self.assertLessEqual(ret, 70)
        ret = reader.testSendPower(2, 1, 2)
        self.assertGreaterEqual(ret, 68)
        self.assertLessEqual(ret, 73)
        ret = reader.testSendPower(2, 1, 3)
        self.assertGreaterEqual(ret, 72)
        self.assertLessEqual(ret, 77)
        ret = reader.testSendPower(2, 1, 4)
        self.assertGreaterEqual(ret, 77)
        self.assertLessEqual(ret, 82)
        ret = reader.testSendPower(2, 1, 5)
        self.assertGreaterEqual(ret, 84)
        self.assertLessEqual(ret, 90)

    def test_RecvSensi(self):
        reader.enterRecvSensi(2, 1)
        time.sleep(7)
        ret = reader.getRecvSensiResult(2, 1)
        self.assertGreaterEqual(ret, 970)

    def test_SetDatt(self):
        reader.setSlaveDatt(2, 0)


    def test_SetRssi(self):
        reader.setSlaveRssi(2, 95)

    def test_SetFreq(self):
        reader.setSlaveFreq(2,29)

    def test_VerifyConfig(self):
        ret = reader.querySlaveInfo(1)
        self.assertEqual(ret[12:], "02005f1d00")

if __name__ == '__main__':
	suite = unittest.TestSuite()
	#suite.addTest(MasterTestCase('test_Eeprom'))
	#suite.addTest(MasterTestCase('test_NandFlash'))
	#suite.addTest(MasterTestCase('test_Rtc'))
	#suite.addTest(MasterTestCase('test_Rs485'))
	#suite.addTest(MasterTestCase('test_SendPower'))
	#suite.addTest(MasterTestCase('test_RecvSensi'))
	#suite.addTest(MasterTestCase('test_SetDeviceSn'))
	#suite.addTest(MasterTestCase('test_SetDeviceIp'))
	#suite.addTest(MasterTestCase('test_SetDeviceMac'))
	#suite.addTest(MasterTestCase('test_SetServerIp'))
	#suite.addTest(MasterTestCase('test_SetCommLink'))
	#suite.addTest(MasterTestCase('test_SetJudgeInterval'))
	#suite.addTest(MasterTestCase('test_SetDatt'))
	#suite.addTest(MasterTestCase('test_SetRssi'))
	#suite.addTest(MasterTestCase('test_SetDirection'))
	#suite.addTest(MasterTestCase('test_VerifySlaveConfig'))
	#suite.addTest(MasterTestCase('test_VerifyMasterConfig'))
	#suite.addTest(SlaveTestCase('test_SetAddr'))
	#suite.addTest(SlaveTestCase('test_SetDirection'))
	suite.addTest(SlaveTestCase('test_SendPower'))
	#suite.addTest(SlaveTestCase('test_RecvSensi'))
	#suite.addTest(SlaveTestCase('test_SetDatt'))
	#suite.addTest(SlaveTestCase('test_SetRssi'))
	#suite.addTest(SlaveTestCase('test_SetFreq'))
	#suite.addTest(SlaveTestCase('test_VerifyConfig'))
	unittest.TextTestRunner().run(suite)
	# suite = unittest.TestLoader().loadTestsFromTestCase(TcpTestCases)

