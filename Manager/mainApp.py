#! /usr/bin/python
# encoding=utf8

import sys
import os
import time
import socket
import binascii
import struct
import json
from PyQt4 import QtCore, QtGui, uic, Qt
from Reader24G import *
from serial.tools.list_ports import comports
_fromUtf8 = QtCore.QString.fromUtf8
from codec_cq import *


class QueryTagThread(QtCore.QThread):
    logSignal = QtCore.pyqtSignal(str)
    tagSignalOut = QtCore.pyqtSignal(str)
    tagSignalIn = QtCore.pyqtSignal(str)

    def __init__(self, reader, interval):
        super(QueryTagThread, self).__init__()
        self.reader = reader
        self.ifQuery = True
        self.queryInterval = interval
        self.outTagList = []
        self.inTagList = []

    def run(self):
        self.logSignal.emit("start query tag info")
        self.outTagList = []
        self.inTagList = []
        while True:
            if not self.ifQuery:
                self.logSignal.emit("stop query tag info")
                self.reader.close()
                break
            tagInfo = self.reader.queryTagInfo(0)
            tagNum = int(tagInfo[0:4], 16)
            showNum = len(tagInfo[4:]) / 18
            curList = []
            for x in range(showNum):
                curList.append(tagInfo[4 + 18 * x:4 + (x + 1) * 18])
            newList = []
            for x in curList:
                if x not in self.outTagList:
                    newList.append(x)
            self.outTagList = curList
            tagMessage = time.ctime() + "\r\n" + "total: %d new: %d \r\n" % (tagNum, len(newList))
            #self.logSignal.emit(time.ctime() + "\r\n" + "receive %d new tag " % len(newList))
            #self.tagSignal.emit(time.ctime() + "\r\n" + "receive %d new tag " % len(newList))
            for x in newList:
                #self.logSignal.emit("flag:"+x[8:10] + " " + x[0:2]+"-"+x[2:4] + "-"+ x[4:6] + "-" + x[6:8])
                tagMessage += x[0:2] + "-" + x[2:4] + "-" + x[4:6] + \
                    "-" + x[6:8] + " rssi: " + str(int(x[16:18], 16)) + "\r\n"
            self.tagSignalOut.emit(tagMessage)
            time.sleep(self.queryInterval)
            tagInfo = self.reader.queryTagInfo(1)
            tagNum = int(tagInfo[0:4], 16)
            showNum = len(tagInfo[4:]) / 18
            curList = []
            for x in range(showNum):
                curList.append(tagInfo[4 + 18 * x:4 + (x + 1) * 18])
            newList = []
            for x in curList:
                if x not in self.inTagList:
                    newList.append(x)
            self.inTagList = curList
            tagMessage = time.ctime() + "\r\n" + "total: %d  new: %d \r\n" % (tagNum, len(newList))
            #self.logSignal.emit(time.ctime() + "\r\n" + "receive %d new tag " % len(newList))
            #self.tagSignal.emit(time.ctime() + "\r\n" + "receive %d new tag " % len(newList))
            for x in newList:
                #self.logSignal.emit("flag:"+x[8:10] + " " + x[0:2]+"-"+x[2:4] + "-"+ x[4:6] + "-" + x[6:8])
                tagMessage += "flag:" + x[8:10] + " " + x[0:2] + "-" + x[2:4] + "-" + x[
                    4:6] + "-" + x[6:8] + " rssi: " + str(int(x[16:18], 16)) + "\r\n"
            self.tagSignalIn.emit(tagMessage)
            time.sleep(self.queryInterval)

    def setDisable(self):
        self.ifQuery = False


class VersionDownloadThread(QtCore.QThread):
    logSignal = QtCore.pyqtSignal(str)
    progressSignal = QtCore.pyqtSignal(str)

    def __init__(self, reader, versionPath):
        super(VersionDownloadThread, self).__init__()
        self.reader = reader
        self.versionPath = versionPath

    def run(self):
        ff = open(self.versionPath, "rb")
        frame_num = 0
        cur_pos = 0
        while True:
            data = ff.read(256)
            print cur_pos
            print len(data)
            if not data:
                break
            flag = (len(data) != 256) and 1 or 0
            try:
                self.reader.downloadVersion(flag, cur_pos, data)
                frame_num += 1
                if frame_num % 20 == 0:
                    self.logSignal.emit("++++++++++++++++")
            except Exception as e:
                print e
                self.reader.close()
                self.progressSignal.emit("error")
                print str(e)
                break

            cur_pos += len(data)
        ff.close()
        self.reader.close()
        self.progressSignal.emit("end")


class MonitorThread(QtCore.QThread):
    monitorSignal = QtCore.pyqtSignal(str)

    def __init__(self, local_ip):
        super(MonitorThread, self).__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local_ip, 5500))
        self.frameCoder = EtcCodec()

    def run(self):
        while True:
            data, addr = self.sock.recvfrom(256)
            decoded_frame = self.frameCoder.decode(data)
            self.monitorSignal.emit(binascii.hexlify(decoded_frame))
            while True:
                decoded_frame = self.frameCoder.decode('')
                if decoded_frame:
                    self.monitorSignal.emit(binascii.hexlify(decoded_frame))
                else:
                    break


class ViewControl(object):

    @QtCore.pyqtSlot(str)
    def acceptLogMessage(self, strMsg):
        self.log(strMsg)

    @QtCore.pyqtSlot(str)
    def acceptTagInfoOutMessage(self, strMsg):
        self.ui.tag_info_out.setText(strMsg)

    @QtCore.pyqtSlot(str)
    def acceptTagInfoInMessage(self, strMsg):
        self.ui.tag_info_in.setText(strMsg)

    @QtCore.pyqtSlot(str)
    def acceptProgressMessage(self, strMsg):
        self.ui.start_download_version.setDisabled(False)
        if str(strMsg) == "end":
            self.log("download success")
        else:
            self.log("download error")

    @QtCore.pyqtSlot(str)
    def acceptMonitorSignal(self, strMsg):

        if strMsg[0:2] == '01':
            self.writeLog(strMsg[0:2] + " " + strMsg[2:16] + " " + strMsg[16:24] +
                          " " + strMsg[24:26] + " " + str(int(str(strMsg[26:28]), 16)))
            tag_id = str(strMsg[16:24])
            slave_number = int(str(strMsg[24:26]))
            key = str(strMsg[16:26])
            if not self.raw_tag_table.has_key(key):
                tag = {}
                tag["time"] = str(strMsg[2:16])
                tag["id"] = tag_id
                tag["slave"] = slave_number
                tag["rssi"] = int(str(strMsg[26:28]), 16)
                tag['count'] = 1
                tag['row_count'] = self.ui.raw_tag_table.rowCount()
                self.raw_tag_table[key] = tag
                self.addRawTagResult(tag)
            else:
                self.raw_tag_table[key]["count"] += 1
                self.raw_tag_table[key]["time"] = str(strMsg[2:16])
                self.raw_tag_table[key]["rssi"] = int(str(strMsg[26:28]), 16)
                self.updateRawTagResult(self.raw_tag_table[key])
            if not self.slave_tag_table.has_key(slave_number):
                slave = {}
                slave['count'] = 1
                slave['tag'] = []
                slave['tag'].append(tag_id)
                self.slave_tag_table[slave_number] = slave
            else:
                self.slave_tag_table[slave_number]['count'] += 1
                if tag_id not in self.slave_tag_table[slave_number]['tag']:
                    self.slave_tag_table[slave_number]['tag'].append(tag_id)
            self.updateSlaveTagTable(slave_number)

        elif strMsg[0:2] == '02':
            self.writeLog(strMsg[0:2] + " " + strMsg[2:16] +
                          " " + strMsg[16:24] + " " + strMsg[24:26])
            tag = {}
            tag["time"] = str(strMsg[2:16])
            tag["id"] = tag_id = str(strMsg[16:24])
            tag["inout"] = int(str(strMsg[24:26]))
            tag["row_count"] = self.ui.judge_tag_table.rowCount()
            self.judge_tag_list.append(tag)
            self.addJudgeTagResult(tag)
            if tag["inout"] == 0:
                self.ui.total_enter_num.setText(
                    str(int(str(self.ui.total_enter_num.text())) + 1))
            elif tag["inout"] == 1:
                self.ui.total_leave_num.setText(
                    str(int(str(self.ui.total_leave_num.text())) + 1))
            else:
                self.ui.total_except_num.setText(
                    str(int(str(self.ui.total_except_num.text())) + 1))
        elif strMsg[0:2] == '04':
            if strMsg[2:4] == '01':
                self.log(u'断开与平台链接')
            elif strMsg[2:4] == '02':
                self.log(u'连接平台成功')
            elif strMsg[2:4] == '03':
                self.log(u'认证失败')
            elif strMsg[2:4] == '04':
                self.log(u'认证成功')
            elif strMsg[2:4] == '05':
                self.log(u'上报进出校信息失败')
            elif strMsg[2:4] == '06':
                self.log(u'上报进出校信息成功')
            elif strMsg[2:4] == '07':
                self.log(u"接收心跳返回消息失败")
            elif strMsg[2:4] == '08':
                self.log(u"收到心跳返回消息")
            else:
                pass
        else:
            self.writeLog(strMsg[0:2] + " " + strMsg[2:16] +
                          " " + strMsg[16:24] + " " + strMsg[24:26])

    def addRawTagResult(self, tag):
        self.ui.raw_tag_table.insertRow(tag['row_count'])
        countWidget = QtGui.QTableWidgetItem()
        countWidget.setText(str(tag['count']))
        tag_idWidget = QtGui.QTableWidgetItem()
        tag_idWidget.setText(tag['id'])
        slave_idWidget = QtGui.QTableWidgetItem()
        slave_idWidget.setText(str(tag['slave']))
        timeWidget = QtGui.QTableWidgetItem()
        timeWidget.setText(tag['time'])
        rssiWidget = QtGui.QTableWidgetItem()
        rssiWidget.setText(str(tag['rssi']))
        self.ui.raw_tag_table.setItem(tag['row_count'], 0, countWidget)
        self.ui.raw_tag_table.setItem(tag['row_count'], 1, tag_idWidget)
        self.ui.raw_tag_table.setItem(tag['row_count'], 2, slave_idWidget)
        self.ui.raw_tag_table.setItem(tag['row_count'], 3, timeWidget)
        self.ui.raw_tag_table.setItem(tag['row_count'], 4, rssiWidget)

    def updateRawTagResult(self, tag):
        row_count = tag['row_count']
        countWidget = self.ui.raw_tag_table.item(row_count, 0)
        countWidget.setText(str(tag['count']))
        timeWidget = self.ui.raw_tag_table.item(row_count, 3)
        timeWidget.setText(tag['time'])
        rssiWidget = self.ui.raw_tag_table.item(row_count, 4)
        rssiWidget.setText(str(tag['rssi']))

    def updateSlaveTagTable(self, slave_number):
        if self.ui.slave_tag_table.rowCount() == 0:
            self.ui.slave_tag_table.insertRow(0)
            self.ui.slave_tag_table.insertRow(1)
            for x in range(4):
                countWidget = QtGui.QTableWidgetItem()
                tagNumberWidget = QtGui.QTableWidgetItem()
                self.ui.slave_tag_table.setItem(0, x, countWidget)
                self.ui.slave_tag_table.setItem(1, x, tagNumberWidget)
        countWidget = self.ui.slave_tag_table.item(0, slave_number - 1)
        tagNumberWidget = self.ui.slave_tag_table.item(1, slave_number - 1)
        countWidget.setText(str(self.slave_tag_table[slave_number]['count']))
        tagNumberWidget.setText(
            str(len(self.slave_tag_table[slave_number]['tag'])))

    def addJudgeTagResult(self, tag):
        self.ui.judge_tag_table.insertRow(tag['row_count'])
        tagIdWidget = QtGui.QTableWidgetItem()
        timeWidget = QtGui.QTableWidgetItem()
        inoutWidget = QtGui.QTableWidgetItem()
        tagIdWidget.setText(tag['id'])
        timeWidget.setText(tag['time'])
        if tag['inout'] == 0:
            inoutWidget.setText(u'进校')
        elif tag['inout'] == 1:
            inoutWidget.setText(u'离校')
        else:
            inoutWidget.setText(u'异常')
            color = QtGui.QColor()
            color.setRed(250)
            inoutWidget.setTextColor(color)
        self.ui.judge_tag_table.setItem(tag['row_count'], 0, tagIdWidget)
        self.ui.judge_tag_table.setItem(tag['row_count'], 1, timeWidget)
        self.ui.judge_tag_table.setItem(tag['row_count'], 2, inoutWidget)

    def __init__(self):
        os.chdir(os.path.dirname(__file__))
        self.ui = uic.loadUi("dialog.ui")
        self.reader = Reader24G()
        self.connectStatus = False
        pe = QtGui.QPalette()
        color = QtGui.QColor()
        color.setRed(250)
        pe.setColor(QtGui.QPalette.WindowText, color)
        self.ui.connect_status.setPalette(pe)
        try:
            local_ip = socket.gethostbyname(socket.getfqdn())
        except Exception as e:
            self.ui.log_window.append(u"请禁用wifi，重启软件")
        self.monitor_thread = MonitorThread(local_ip)
        self.monitor_thread.monitorSignal.connect(self.acceptMonitorSignal)
        self.monitor_thread.start()
        self.monitorStatus = False
        self.raw_tag_table = {}
        self.judge_tag_list = []
        self.slave_tag_table = {}
        self.logFile = None
        configFile = open("config.json", "r")
        self.config = json.load(configFile)
        configFile.close()
        self.ui.ip_address.setText(self.config['ipaddr'])

    def connectSlots(self):
        QtCore.QObject.connect(self.ui.clear_log,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onClearLog)
        QtCore.QObject.connect(self.ui.query_slave,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onQuerySlave)
        QtCore.QObject.connect(self.ui.set_slave_addr,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetSlaveAddr)
        QtCore.QObject.connect(self.ui.set_slave_direction,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetSlaveDirection)
        QtCore.QObject.connect(self.ui.set_master_rtc,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetRtc)
        QtCore.QObject.connect(self.ui.read_master_rtc,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onReadRtc)
        QtCore.QObject.connect(self.ui.browse_version,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onBrowseVersion)
        QtCore.QObject.connect(self.ui.start_download_version,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onStartDownloadVersion)
        QtCore.QObject.connect(self.ui.reset_device,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onResetDevice)
        QtCore.QObject.connect(self.ui.set_judge_interval,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetJudgeInterval)
        QtCore.QObject.connect(self.ui.set_comm_link,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetCommLink)
        QtCore.QObject.connect(self.ui.read_master_config,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onReadMasterConfig)
        QtCore.QObject.connect(self.ui.connect_reader,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onConnectReader)
        QtCore.QObject.connect(self.ui.query_local_ip,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onQueryLocalIp)
        QtCore.QObject.connect(self.ui.set_local_ip,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetLocalIp)
        QtCore.QObject.connect(self.ui.query_remote_ip,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onQueryRemoteIp)
        QtCore.QObject.connect(self.ui.set_remote_ip,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetRemoteIp)
        QtCore.QObject.connect(self.ui.set_slave_rssi,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetSlaveRssi)
        QtCore.QObject.connect(self.ui.set_slave_datt,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onSetSlaveDatt)
        QtCore.QObject.connect(self.ui.start_monitor,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onStartMonitor)
        QtCore.QObject.connect(self.ui.clear_monitor,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onClearMonitor)
        QtCore.QObject.connect(self.ui.read_app_id,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onReadAppDeviceId)
        QtCore.QObject.connect(self.ui.set_app_id,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onWriteAppDeviceId)
        QtCore.QObject.connect(self.ui.export_monitor_result,  QtCore.SIGNAL(
            _fromUtf8("clicked()")), self.onExportResult)


    def run(self):
        self.ui.show()

    def log(self, logString):
        self.ui.log_window.append(logString)

    def openReader(self):
        ipAddr = str(self.ui.ip_address.displayText())
        try:
            self.reader.open(0, ipAddr, 5000)
        except Exception as e:
            self.log(u"链接设备失败，请检查IP设置")
            self.connectStatus = False
        else:
            self.log(u"链接设备成功")
            self.connectStatus = True
            self.ui.connect_reader.setText(u"断链")
            self.ui.connect_status.setText(u"设备已连接")
            pe = QtGui.QPalette()
            color = QtGui.QColor()
            color.setGreen(250)
            pe.setColor(QtGui.QPalette.WindowText, color)
            self.ui.connect_status.setPalette(pe)

    def closeReader(self):
        self.reader.close()
        self.connectStatus = False
        self.log(u"设备已断开")
        self.ui.connect_reader.setText(u"链接")
        self.ui.connect_status.setText(u"设备未连接")
        pe = QtGui.QPalette()
        color = QtGui.QColor()
        color.setRed(250)
        pe.setColor(QtGui.QPalette.WindowText, color)
        self.ui.connect_status.setPalette(pe)

    def onClearLog(self):
        self.ui.log_window.clear()

    def onConnectReader(self):
        if not self.connectStatus:
            self.openReader()
        else:
            self.closeReader()

    def onQueryLocalIp(self):
        device_ip = self.reader.queryIpAddress()
        addr = socket.inet_ntoa(binascii.unhexlify(device_ip[0:8]))
        netmask = socket.inet_ntoa(binascii.unhexlify(device_ip[8:16]))
        gateway = socket.inet_ntoa(binascii.unhexlify(device_ip[16:24]))
        self.ui.local_ip_addr.setText(addr)
        self.ui.local_net_mask.setText(netmask)
        self.ui.local_gate_way.setText(gateway)
        self.log(u"读取本地IP成功")
        self.log(u"设备地址: " + addr)
        self.log(u"子网掩码: " + netmask)
        self.log(u"网关: " + gateway)

    def onSetLocalIp(self):
        ipAddr = self.ui.local_ip_addr.displayText()
        netMask = self.ui.local_net_mask.displayText()
        gateway = self.ui.local_gate_way.displayText()
        ipAddrStr = binascii.hexlify(socket.inet_aton(str(ipAddr)))
        netMaskStr = binascii.hexlify(socket.inet_aton(str(netMask)))
        gatewayStr = binascii.hexlify(socket.inet_aton(str(gateway)))
        self.reader.setDeviceIp(ipAddrStr, netMaskStr, gatewayStr)
        self.log(u"设置本地IP成功")

    def onQueryRemoteIp(self):
        server_ip = self.reader.queryServerIp()
        addr = socket.inet_ntoa(server_ip[0:4])
        self.ui.server_ip_addr.setText(addr)
        port = ord(server_ip[4]) * 256 + ord(server_ip[5])
        self.ui.server_ip_port.setValue(port)
        self.log(u"查询连接平台IP成功")
        self.log(u"连接平台IP: " + addr)
        self.log(u"连接平台端口: " + str(port))

    def onSetRemoteIp(self):
        serverAddr = self.ui.server_ip_addr.displayText()
        serverAddrStr = binascii.hexlify(socket.inet_aton(str(serverAddr)))
        port = self.ui.server_ip_port.value()
        self.reader.setServerIp(serverAddrStr, port)
        self.log(u"设置连接平台IP成功")

    def onQuerySlave(self):
        self.ui.query_slave.setDisabled(True)
        try:
            slaveInfo = self.reader.querySlaveInfo(1)
            numberOfRf = int(slaveInfo[0:2])
            self.log(u"从设备信息: ")
            self.log(u"从设备个数: " + str(numberOfRf))
            self.log("-------------------------------")
            for x in range(numberOfRf):
                self.log(u"从设备地址: " +
                         str(int(slaveInfo[2 + x * 10:4 + x * 10], 16)))
                self.log(u"从设备DATT:" +
                         str(int(slaveInfo[4 + x * 10: 6 + x * 10], 16)))
                self.log(u"从设备RSSI: " +
                         str(int(slaveInfo[6 + x * 10: 8 + x * 10], 16)))
                self.log(
                    u"从设备freq: 24" + str(int(slaveInfo[8 + x * 10: 10 + x * 10], 16)) + "MHz")
                direction = int(slaveInfo[10 + x * 10: 12 + x * 10], 16)
                if direction == 0:
                    self.log(u"从设备方向: 指向校外")
                else:
                    self.log(u"从设备方向: 指向校内")
                self.log("++++++++++++++++++++++++++")
        except Exception as e:
            print str(e)
            self.log(u"读取从设备信息失败")
        finally:
            self.ui.query_slave.setDisabled(False)

    def onSetSlaveAddr(self):
        oldAddr = self.ui.old_slave_addr.value()
        newAddr = self.ui.new_slave_addr.value()
        self.reader.setSlaveAddr(oldAddr, newAddr)
        self.log(u"设置从设备地址成功")

    def onSetSlaveDirection(self):
        addr = self.ui.slave_direction_addr.value()
        direction = self.ui.slave_direction.currentIndex()
        self.reader.setSlaveDirection(addr, direction)
        self.log(u"设置从设备方向成功")

    def onSetSlaveDatt(self):
        addr = self.ui.slave_datt_addr.value()
        datt = self.ui.slave_datt_value.value()
        self.reader.setSlaveDatt(addr, datt)
        self.log(u"设置从设备DATT成功")

    def onSetSlaveRssi(self):
        addr = self.ui.slave_rssi_addr.value()
        rssi = self.ui.slave_rssi.value()
        try:
            self.reader.setSlaveRssi(addr, rssi)
        except Exception as e:
            print e
            self.log(u"设置从设备RSSI失败")
        else:
            self.log(u"设置从设备RSSI成功")

    def onSetSlaveFreq(self):
        addr = self.ui.slave_freq_addr.value()
        freq = self.ui.slave_freq.value()
        self.openReader()
        self.reader.setSlaveFreq(addr, freq)
        self.log("set slave freq success")
        self.closeReader()

    def onSetRtc(self):
        date = self.ui.dateTimeEdit.date()
        time = self.ui.dateTimeEdit.time()
        year = chr(date.year() / 100) + chr(date.year() % 100)
        month = chr(date.month())
        day = chr(date.day())
        hour = chr(time.hour())
        minute = chr(time.minute())
        second = chr(time.second())
        timeStr = year + month + day + hour + minute + second
        self.reader.setRtc(timeStr)
        self.log(u"设置RTC成功")

    def onReadRtc(self):
        rtcTime = self.reader.readRtc()
        year = str(int(rtcTime[0:2], 16)) + str(int(rtcTime[2:4], 16))
        month = str(int(rtcTime[4:6], 16))
        day = str(int(rtcTime[6:8], 16))
        hour = str(int(rtcTime[8:10], 16))
        minute = str(int(rtcTime[10:12], 16))
        second = str(int(rtcTime[12:14], 16))
        date = QtCore.QDate()
        date.setDate(int(year), int(month), int(day))
        time = QtCore.QTime()
        time.setHMS(int(hour), int(minute), int(second))
        self.ui.dateTimeEdit.setDate(date)
        self.ui.dateTimeEdit.setTime(time)
        self.log(u"读取RTC成功")
        self.log(year + u"年" + month + u"月" + day + u"日" +
                 hour + u"时" + minute + u"分" + second + u"秒")

    def onSetDeviceSn(self):
        deviceSn = self.ui.master_sn.displayText()
        if(len(str(deviceSn)) != 20):
            self.log("device sn length not correct!")
            return
        self.openReader()
        self.reader.setDeviceSn(str(deviceSn))
        self.log("set device sn success")
        self.closeReader()

    def onReadDeviceSn(self):
        deviceSn = self.reader.readDeviceSn()
        self.log(u"设备出厂序列号：" + deviceSn)

    def onSetIpAddr(self):
        ipAddr = self.ui.ethernet_addr.displayText()
        netMask = self.ui.ethernet_mask.displayText()
        gateway = self.ui.ethernet_gateway.displayText()
        ipAddrStr = binascii.hexlify(socket.inet_aton(str(ipAddr)))
        netMaskStr = binascii.hexlify(socket.inet_aton(str(netMask)))
        gatewayStr = binascii.hexlify(socket.inet_aton(str(gateway)))
        self.openReader()
        self.reader.setDeviceIp(ipAddrStr, netMaskStr, gatewayStr)
        self.log("set device ip success")
        self.closeReader()

    def onReadTagInfo(self):
        self.ui.stop_read_tag.setDisabled(False)
        self.ui.read_tag_info.setDisabled(True)
        self.ui.tag_info_out.setText("")
        self.ui.tag_info_in.setText("")
        queryInterval = self.ui.read_tag_cycle.value()
        self.openReader()
        self.thread = QueryTagThread(self.reader, queryInterval)
        self.thread.logSignal.connect(self.acceptLogMessage)
        self.thread.tagSignalOut.connect(self.acceptTagInfoOutMessage)
        self.thread.tagSignalIn.connect(self.acceptTagInfoInMessage)
        self.thread.start()

    def onStopReadTag(self):
        self.thread.setDisable()
        self.thread.wait()
        self.ui.stop_read_tag.setDisabled(True)
        self.ui.read_tag_info.setDisabled(False)

    def onBrowseVersion(self):
        dialog = QtGui.QFileDialog()
        name = dialog.getOpenFileName()
        self.ui.version_path.setText(name)

    def onStartDownloadVersion(self):
        versionPath = str(self.ui.version_path.displayText())
        from os import path
        versionPath = path.abspath(versionPath)
        self.ui.start_download_version.setDisabled(True)
        try:
            self.reader.open(0, "222.255.255.253", 5000)
        except Exception as e:
            self.log(u"链接设备失败，请检查IP设置")
            self.ui.start_download_version.setDisabled(False)
        self.thread = VersionDownloadThread(self.reader, versionPath)
        self.thread.logSignal.connect(self.acceptLogMessage)
        self.thread.progressSignal.connect(self.acceptProgressMessage)
        self.thread.start()
        self.log("start download")

    def onReadDeivceIp(self):
        self.openReader()
        device_ip = self.reader.queryIpAddress()
        self.closeReader()
        addr = socket.inet_ntoa(binascii.unhexlify(device_ip[0:8]))
        netmask = socket.inet_ntoa(binascii.unhexlify(device_ip[8:16]))
        gateway = socket.inet_ntoa(binascii.unhexlify(device_ip[16:24]))
        self.log("read device ip success")
        self.log("address: " + addr)
        self.log("netmask: " + netmask)
        self.log("gateway: " + gateway)

    def onResetDevice(self):
        self.reader.resetReader()
        self.closeReader()
        self.log(u"复位成功")

    def onSetJudgeInterval(self):
        interval = self.ui.judge_interval.value()
        self.reader.setJudgeInterval(interval * 1000)
        self.log(u"设置判决时间成功")

    def onSetCommLink(self):
        comm_link = self.ui.comm_link.currentIndex()
        self.reader.setCommLink(comm_link)
        if comm_link:
            self.log(u"设置连接平台方式为4G网络")
        else:
            self.log(u"设置连接平台方式为以太网")

    def onQueryTagLog(self):
        query_date = self.ui.query_date.value()
        query_flag = self.ui.query_flag.currentIndex()
        query_index = self.ui.query_index.value()
        self.openReader()
        tag_log = self.reader.queryTagLog(query_date, query_flag, query_index)
        self.closeReader()
        (count, ) = struct.unpack("!H", tag_log[0:2])
        tag_id = binascii.hexlify(tag_log[2:6])
        time = binascii.hexlify(tag_log[6:13])
        self.log("toal number: %d " % count)
        self.log("index: " + str(query_index))
        print count
        print query_index
        if count <= query_index:
            self.log("tag not exist")
        else:
            self.log("tag id: " + tag_id)
            self.log("time: " + time)

    def onReadMasterConfig(self):
        master_config = self.reader.queryMasterConfig()
        ip_addr = socket.inet_ntoa(master_config[0:4])
        net_mask = socket.inet_ntoa(master_config[4:8])
        gate_way = socket.inet_ntoa(master_config[8:12])
        server_ip = socket.inet_ntoa(master_config[12:16])
        (server_port, ) = struct.unpack("!H", master_config[16:18])
        (judge_time, ) = struct.unpack("!I", master_config[18:22])
        comm_link = ord(master_config[22])
        version = master_config[23:]
        self.log(u"基本配置")
        self.log("-----------------------")
        self.log(u"IP地址: " + ip_addr)
        self.log(u"子网掩码: " + net_mask)
        self.log(u"网关: " + gate_way)
        self.log(u"连接平台IP地址: " + server_ip)
        self.log(u"连接平台端口: " + str(server_port))
        self.log(u"判决时间: " + str(judge_time / 1000) + u"  秒")
        if comm_link:
            self.log(u"连接平台方式: 4G网")
        else:
            self.log(u"连接平台方式: 以太网")
        self.log(u"软件版本: " + str(version))

    def onTestNandFlash(self):
        self.openReader()
        self.reader.testNandFlash()
        self.log("test nand flash success")
        self.closeReader()

    def onWriteMacAddr(self):
        mac_addr = str(self.ui.mac_address.displayText())
        mac_addr_hex = binascii.unhexlify(mac_addr.replace("-", ""))
        self.openReader()
        self.reader.setMacAddr(mac_addr_hex)
        self.closeReader()
        self.log("write mac address success")

    def onReadMacAddr(self):
        self.openReader()
        mac_addr = self.reader.readMacAddr()
        mac_addr_str = binascii.hexlify(mac_addr)
        self.closeReader()
        self.log("read mac address: " + mac_addr_str[0:2] + "-" + mac_addr_str[2:4] + "-"
                 + mac_addr_str[4:6] + "-" + mac_addr_str[6:8] + "-" + mac_addr_str[8:10] + "-" + mac_addr_str[10:12])

    def onStartMonitor(self):
        if self.monitorStatus:
            self.monitorStatus = False
            self.ui.start_monitor.setText(u'开始监控')
            self.ui.raw_tag_table.setSortingEnabled(True)
            self.ui.slave_tag_table.setSortingEnabled(True)
            self.ui.judge_tag_table.setSortingEnabled(True)
            self.closeLogFile()
            self.reader.stopMonitor()
        else:
            self.ui.raw_tag_table.setSortingEnabled(False)
            self.ui.slave_tag_table.setSortingEnabled(False)
            self.ui.judge_tag_table.setSortingEnabled(False)
            self.monitorStatus = True
            self.ui.start_monitor.setText(u'停止监控')
            self.ui.raw_tag_table.setRowCount(0)
            self.ui.slave_tag_table.setRowCount(0)
            self.ui.judge_tag_table.setRowCount(0)
            self.ui.total_enter_num.setText("0")
            self.ui.total_leave_num.setText("0")
            self.ui.total_except_num.setText("0")
            self.raw_tag_table = {}
            self.slave_tag_table = {}
            self.judge_tag_list = []
            self.createLogFile()
            self.reader.startMonitor()

    def onClearMonitor(self):
        self.ui.raw_tag_table.setRowCount(0)
        self.ui.slave_tag_table.setRowCount(0)
        self.ui.judge_tag_table.setRowCount(0)
        self.ui.total_enter_num.setText("0")
        self.ui.total_leave_num.setText("0")
        self.ui.total_except_num.setText("0")
        self.raw_tag_table = {}
        self.slave_tag_table = {}
        self.judge_tag_list = []

    def createLogFile(self):
        if self.ui.write_log_flag.isChecked():
            name = time.strftime("%Y-%m-%d.log")
            self.logFile = open(name, "a+")
            self.logFile.write("start monitor\n")
            self.logFile.write("-------------------\n")
        else:
            self.logFile = None

    def closeLogFile(self):
        if self.logFile:
            self.logFile.write("------------------\n")
            self.logFile.write("end monitor\n")
            self.logFile.flush()
            self.logFile.close()
            self.logFile = None

    def writeLog(self, myStr):
        if self.logFile:
            self.logFile.write(myStr + "\n")

    def onReadAppDeviceId(self):
        ret = self.reader.readAppDeviceId()
        self.ui.app_device_id.setText(ret)
        self.log(u"读取设备号成功")

    def onWriteAppDeviceId(self):
        deviceId = str(self.ui.app_device_id.displayText())
        self.reader.setAppDeviceId(deviceId)
        self.log(u"设置设备号成功")

    def onExportResult(self):
        self.exportFile = open("result.txt", "w")
        self.exportFile.write("===============监控结果=================\n\n")
        self.exportFile.write("------------结果汇总----------\n")
        if self.slave_tag_table.has_key(1):
            self.exportFile.write("读头一：\n")
            self.exportFile.write("    读取标签 " + str(len(self.slave_tag_table[1]['tag'])) + " 张\n")
            self.exportFile.write("    读取次数 " + str(self.slave_tag_table[1]['count']) + " 次\n")
        if self.slave_tag_table.has_key(2):
            self.exportFile.write("读头二：\n")
            self.exportFile.write("    读取标签 " + str(len(self.slave_tag_table[2]['tag'])) + " 张\n")
            self.exportFile.write("    读取次数 " + str(self.slave_tag_table[2]['count']) + " 次\n")
        if self.slave_tag_table.has_key(3):
            self.exportFile.write("读头三:\n")
            self.exportFile.write("    读取标签 " + str(len(self.slave_tag_table[3]['tag'])) + " 张\n")
            self.exportFile.write("    读取次数 " + str(self.slave_tag_table[3]['count']) + " 次\n")
        if self.slave_tag_table.has_key(4):
            self.exportFile.write("读头四:\n")
            self.exportFile.write("    读取标签 " + str(len(self.slave_tag_table[4]['tag'])) + " 张\n")
            self.exportFile.write("    读取次数 " + str(self.slave_tag_table[4]['count']) + " 次\n")

        self.exportFile.write("\n\n------------读取明细----------\n")

        if self.slave_tag_table.has_key(1):
            tnumber = len(self.slave_tag_table[1]['tag'])
            self.exportFile.write("\n读头一 标签总数" + str(tnumber) + "张\n")
            cols = 0
            for x in self.slave_tag_table[1]['tag']:
                self.exportFile.write(x + "  ")
                cols += 1 
                if cols == 10:
                    cols = 0 
                    self.exportFile.write("\n")
            self.exportFile.write("\n")

        if self.slave_tag_table.has_key(2):
            tnumber = len(self.slave_tag_table[2]['tag'])
            self.exportFile.write("\n读头二 标签总数" + str(tnumber) + "张\n")
            cols = 0
            for x in self.slave_tag_table[2]['tag']:
                self.exportFile.write(x + "  ")
                cols += 1 
                if cols == 10:
                    cols = 0 
                    self.exportFile.write("\n")
            self.exportFile.write("\n")
        if self.slave_tag_table.has_key(3):
            tnumber = len(self.slave_tag_table[3]['tag'])
            self.exportFile.write("\n读头三 标签总数" + str(tnumber) + "张\n")
            cols = 0 
            for x in self.slave_tag_table[3]['tag']:
                self.exportFile.write(x + "  ")
                cols += 1 
                if cols == 10:
                    cols = 0 
                    self.exportFile.write("\n")
            self.exportFile.write("\n")

        if self.slave_tag_table.has_key(4):
            tnumber = len(self.slave_tag_table[4]['tag'])
            self.exportFile.write("\n读头四 标签总数" + str(tnumber) + "张\n")
            cols = 0
            for x in self.slave_tag_table[4]['tag']:
                self.exportFile.write(x + "  ")
                cols += 1 
                if cols == 10:
                    cols = 0 
                    self.exportFile.write("\n")
            self.exportFile.write("\n")

        self.exportFile.write("\n\n------------判决结果----------\n")
        enter_num = 0 
        leave_num = 0 
        except_num = 0
        for x in self.judge_tag_list:
            if x['inout'] == 0:
                enter_num += 1 
            elif x['inout'] == 1:
                leave_num += 1 
            else:
                except_num += 1 
        self.exportFile.write("进校 " + str(enter_num) + " 离校 " + str(leave_num) + " 异常 " + str(except_num) + "\n\n")
        self.exportFile.write("\n----进校----\n")
        cols = 0
        for x in self.judge_tag_list:
            if x['inout'] == 0:
                self.exportFile.write(x['id'] + "  ")
                cols += 1 
                if cols == 10:
                    cols = 0
                    self.exportFile.write("\n")

        self.exportFile.write("\n----离校----\n")
        cols = 0
        for x in self.judge_tag_list:
            if x['inout'] == 1:
                self.exportFile.write(x['id'] + "  ")
                cols += 1 
                if cols == 10:
                    cols = 0 
                    self.exportFile.write("\n")

        cols = 0
        self.exportFile.write("\n----异常----\n")
        for x in self.judge_tag_list:
            if x['inout'] == 4:
                self.exportFile.write(x['id'] + "  ")
                cols += 1 
                if cols == 10:
                    cols = 0 
                    self.exportFile.write("\n")


        self.exportFile.write("\n\n-------------流水日志------------\n")
        self.exportFile.write("id      " + " 次数  " + "地址       " + "时间       " + "rssi  \n")
        for k, x in self.raw_tag_table.iteritems():
            self.exportFile.write(x['id'] + " " + "{0:4d}".format(x['count']) + "   " + str(x['slave']) + "     " + x['time'] + "  " + str(x['rssi']) + "\n")

        self.exportFile.close()
        self.log(u"导出结果到rexult.txt")


if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    viewControl = ViewControl()
    viewControl.connectSlots()
    viewControl.run()
    sys.exit(app.exec_())
