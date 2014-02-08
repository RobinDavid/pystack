#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Author: Robin David
License: GNU GPLv3
Repo: https://github.com/RobinDavid

Copyright (c) 2012 Robin David

PyStack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or 
any later version http://www.gnu.org/licenses/. 
'''
from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, SIGNAL, SLOT, PYQT_VERSION_STR, QT_VERSION_STR, QUrl, QByteArray
from PyQt4.QtGui import * #QApplication, QMainWindow
import random
import sys
import re

import clientweb # Ui_Dialog

from pystack.layers.tcp_session import TCPSession
from pystack.layers.tcp_application import TCPApplication
from pystack.pystack import PyStack


def binvalue(val, bitsize): #Return the binary value as a string of the given size 
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "binary value larger than the expected size"
    return binval.zfill(bitsize)

def nsplit(s, n):#Split a list into sublists of size "n"
    return [s[k:k+n] for k in xrange(0, len(s), n)]

def int_to_string(val, size):
    return ''.join([chr(int(x,2)) for x in nsplit(binvalue(val, size), 8)])


class SteganoApplication(TCPApplication):
    '''
    !!! This TCPApplication is the same than in stegano_chat. Take a look at it for further comments
    '''
    def __init__(self, win=None):
        TCPApplication.__init__(self)
        
        self.win = win
        
        #For receiving purposes
        self.reassembled_stream = ""
        self.reception_finished = True
        
        #For sending purposes
        self.hidden_to_stream = ""
        self.position = 0
        self.streaming_finished = True
        
        #Diffie hellman stuff
        self.modulus = 4294967291 #Nearest prime number from pow(2,32) (4294967296) stored on 4 bytes so that the maximum value will be coded on 4 bytes
        self.x = random.randint(1,100)
        self.g = random.randint(1,65535)
        self.sharedkey = None #Diffie Hellman key
        self.sourceport = None
        self.key = None
        self.ctr_input = None
        self.ctr_output = None
        self.cipher_input = None
        self.cipher_output = None
        
    def packet_received(self, packet, **kwargs):
        self.win.regular_data_received(packet)
        

    def hidden_chunk_received(self, chunk, **kwargs):
        print("Hidden chunk:",chunk)
        self.win.hidden_chunk_received(chunk)
        self.reassembled_stream += chunk

    def send_hidden_packet(self, packet):
        self.hidden_to_stream += packet
        self.streaming_finished = False

    def get_bytes(self, nb):
        if not self.streaming_finished:
            s = self.hidden_to_stream[self.position:self.position+nb]
            while len(s) < nb:
                s+="\x00"
            bytes = s #int(''.join([binvalue(x,8) for x in s]),2)
            self.position += nb
            if self.position >= len(self.hidden_to_stream):
                self.streaming_finished = True
                self.position = 0
                return bytes, True
            else:
                return bytes, False
        else:
            return None, True
    
    def generate_keys(self, packet):
        self.sourceport = packet.sport #Used as g of diffie hellman exchange
        print "A(seq):",packet.seq,"  a:",self.x,"  mod:",self.modulus
        self.sharedkey = pow(packet.seq,self.x,self.modulus) #Diffie hellman (g^y)^x mod p
        print("Shared key:"+str(self.sharedkey))
        
        from Crypto.Hash import SHA256
        sha = SHA256.new()
        sha.update(str(self.sharedkey))
        self.key = sha.digest() #Now have a nice key of 256 bits
        
        from Crypto.Util import Counter
        self.ctr_input = Counter.new(128,initial_value=self.sharedkey)
        self.ctr_output = Counter.new(128,initial_value=self.sharedkey)
        
        from Crypto.Cipher import AES
        self.cipher_input = AES.new(self.key, AES.MODE_CTR, counter=self.ctr_input)
        self.cipher_output = AES.new(self.key, AES.MODE_CTR, counter=self.ctr_output)

    def cipher(self,value):
        print "Cipher:", value
        res = self.cipher_output.encrypt(value)
        print "Ciphered:",res
        final= int(''.join([binvalue(x,8) for x in res]),2)
        print "Inted:", final
        return final
    
    def decipher(self, value, size):
        print "Inted:",value
        value = int_to_string(value, size)
        print "Ciphered:", value
        final = self.cipher_input.decrypt(value)
        print "Decipherd:",final
        return final
    
    def hook_incoming(self, packet, **kwargs):
        if packet.flags in (2, 18):
            self.generate_keys(packet)
            if packet.flags == 2:
                id = self.lowerLayers["default"].connectionID
                self.win = self.lowerLayers["default"].lowerLayers["default"].upperLayers[(id[2],id[3])].app.win #Please close your eyes it so ugly
                self.win.set_tcpapp(self)
        else:    
            if kwargs["IP"]["flags"] == 2:
                self.reception_finished = False
                
                s = ""
                s += self.decipher(kwargs["IP"]["id"], 16)
                s += self.decipher(packet.window, 16)
                s += self.decipher(packet.urgptr, 16)
                for opt in packet.options:
                    if opt[0] == "Timestamp":
                        s += self.decipher(opt[1][0], 32)
                        #s += int_to_string(opt[1][1], 32)
                    
                self.hidden_chunk_received(s)
            
            else:
                if not self.reception_finished:
                    self.reception_finished = True
                    self.win.hidden_data_received(self.reassembled_stream)
                    self.reassembled_stream=""
                    print("Hidden message:"+self.reassembled_stream)
            
            if packet.flags & 8 == 8: #Means flags contain PSH
                if not self.reception_finished:
                    print("End of regular data but not of hidden data")
                    self.win.end_regular_data()
                    #Should redo a request to get further replies from server
    
    def hook_outgoing(self, packet, **kwargs):
        if kwargs["TCP"]["flags"] in (2, 18): 
            if kwargs["TCP"]["flags"] == 2:
                print "SYN g:",self.g
                seq = pow(self.g,self.x,self.modulus) #When send SYN it us who send the g
                kwargs["TCP"]["sport"] = self.g  #Change the source port in the packet that will be sent
                session = self.lowerLayers["default"]  #Get the underlying session
                session.localPort = self.g  #Modify it's localPort
                id = session.connectionID  #Get the id (in order to modify it)
                session.lowerLayers["default"].unregister_upper_layer(id)  #Unregister this session from tcp
                id = (id[0], id[1], id[2], self.g)  #Modify the id
                session.connectionID = id  #Modify it in the session
                session.lowerLayers["default"].register_upper_layer(id, session)  #Register again the session in tcp with the new id
            else:
                print "SYNACK  sourceport:",self.sourceport
                seq = pow(self.sourceport, self.x,self.modulus)
                
            kwargs["TCP"]["seq"] = seq
            self.lowerLayers["default"].seqNo = seq
            self.lowerLayers["default"].nextAck = seq+1
              
        elif not self.streaming_finished:
            size = 0
            for proto,field,nb_bytes in (("IP","id", 2),("TCP","window",2), ("TCP","urgptr", 2)):
                value, res = self.get_bytes(nb_bytes)
                if value:
                    kwargs["IP"]["flags"] = 2
                    size += 2
                    kwargs[proto][field] = self.cipher(value)
            
                    
            t1, res = self.get_bytes(4)
            size +=4
            
            if t1:
                t1 = self.cipher(t1) if t1 else 0

                if kwargs["TCP"].has_key("options"):
                    kwargs["TCP"]["options"].append(("Timestamp",(t1,0)))
                else:
                    kwargs["TCP"]["options"] = [("Timestamp",(t1,0))]
            
            if res:
                kwargs["IP"]["flags"] = 2
            self.win.hidden_chunk_sent(size)
        return packet, kwargs
    
    def run(self):
        self.win.show()

class ClientWindow(QDialog, clientweb.Ui_Dialog):
    ''' Client window that allow to send HTTP request both genuinely and covertly and to show the result of the two '''
    def __init__(self, parent=None):
        super(QDialog, self).__init__(parent)
        self.setupUi(self)
        
        self.tcpapp = None
        
        self.connect(self.send_regular, SIGNAL("clicked()"), self.regular_data_button_clicked)
        self.connect(self.send_hidden, SIGNAL("clicked()"), self.hidden_data_button_clicked)
        self.connect(self, SIGNAL("data_received"), self.update_data_received)
        self.connect(self, SIGNAL("hidden_data_received"), self.update_hidden_received)
        
    def set_tcpapp(self,app):
        self.tcpapp = app
    
    def send_regular_data(self, string):
        self.tcpapp.send_packet(str(string))
        #print("Regular text:"+string)
        
    def send_hidden_data(self, string):
        self.tcpapp.send_hidden_packet(str(string))
        #print("Hidden text:"+string)
        
    def regular_data_button_clicked(self):
        text = str(self.textedit_regular.toPlainText())
        #self.view_regular.addItem("Me:"+text)
        #self.textedit_regular.setPlainText("")
        if str(self.process_regular.text()).startswith("[Resend to continue]"):
            self.process_regular.setText(str(self.process_regular.text())[19:])
        self.send_regular_data(re.sub("\n","\r\n",text))
    
    def hidden_data_button_clicked(self):
        text = str(self.textedit_hidden.toPlainText())
        #self.view_hidden.addItem("Me:"+text)
        #self.textedit_hidden.setPlainText("")
        self.process_hidden.setText(self.process_hidden.text()+text)
        
        self.send_hidden_data(re.sub("\n","\r\n",text))
    
    def regular_data_received(self,text):
        text= re.sub(".*<html>","<html>",text)
        if re.search("<html>",text):
            self.emit(SIGNAL("data_received"), text)
        else:
            print "Headers not added in page"
    
    def update_data_received(self, text): #Need this method to execute the code in the main thread
        print "Signal received !", text
        self.regularWebView.setHtml(text)
    
    def hidden_data_received(self, text):
        text= ''.join(re.split("(.*)(<html>.*)",text)[-2:])
        if re.search("<html>",text):
            self.emit(SIGNAL("hidden_data_received"), text)
    
    def update_hidden_received(self, text):
        print text
        self.hiddenWebView.setHtml(re.sub(".*<html>","<html>",text))
        self.process_regular.setText("")
    
    def hidden_chunk_received(self, chk):
        self.process_regular.setText(self.process_regular.text()+chk)
    
    def hidden_chunk_sent(self, size):
        txt = self.process_hidden.text()
        self.process_hidden.setText(txt[size:])
    
    def end_regular_data(self):
        self.process_regular.setText("[Resend to continue]"+self.process_regular.text())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Stegano HTTP Client")
    win = ClientWindow()

    app2 = QApplication.instance()

    stack = PyStack()
    stack.run(doreactor=False)

    steganoapp = SteganoApplication(win)
    stack.register_tcp_application(steganoapp)
    
    win.set_tcpapp(steganoapp)
    
    steganoapp.run()
    
    steganoapp.connect("192.168.0.13", 80)
    
    win.textedit_regular.setPlainText("GET / HTTP/1.1\nHost: 192.168.0.13\nUser-Agent: Mozilla/5.0\nKeep-Alive: 300\nConnection: keep-alive\n\n")
    win.textedit_hidden.setPlainText("GET / HTTP/1.1\nHost: 192.168.0.13\nUser-Agent: Mozilla/5.0\nKeep-Alive: 300\nConnection: keep-alive\n\n")

    app.exec_()
    
    stack.stop()
