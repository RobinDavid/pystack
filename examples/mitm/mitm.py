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
import re
import sys

from PyQt4 import QtNetwork
from PyQt4.QtCore import (Qt, SIGNAL)
from PyQt4.QtGui import QDialog, QApplication, QMessageBox

from scapy.all import IP

from pystack.layers.ethernet import EthernetProtocol
from pystack.layers.ip import IPProtocol
from pystack.layers.arp import ARPProtocol
from pystack.layers.tcp_session import State_ESTABLISHED


from tcpmodif import TCPProtoModified
from mitm_tcpsession import SessionMITM, MITMApplication
import window
from pystack.nfqueue_utils import NFQueueManager



class MyWindowMITM(QDialog, window.Ui_Dialog):
    def __init__(self, parent=None):
        super(QDialog, self).__init__(parent)
        self.setupUi(self)
        
        self.hooked = False
        
        #-- Network info
        self.interface = "eth0"
        self.ip = QtNetwork.QNetworkInterface.interfaceFromName(self.interface).addressEntries()[0].ip().toString() #A way like another to get local IP
        
        #-- Nfqueue stuff
        self.ip = self.ip
        self.qmi = None
        self.qmo = None
        self.rulei = ""
        self.ruleo = ""
        
        #-- Stack stuff
        self.ethp = EthernetProtocol(self.interface)
        self.ipp = IPProtocol()
        self.ethp.register_layer(self.ipp)
        arpp = ARPProtocol(self.interface)
        self.ethp.register_layer(arpp)
        self.tcpp = TCPProtoModified(self)
        self.ipp.register_layer(self.tcpp)
        self.ethp.start_listening(doreactor=False)        
        self.session = None
        self.app = None
        
        #-- Signal slot stuff
        self.connect(self.listenbutton, SIGNAL("clicked()"), self.listenbutton_clicked)
        self.connect(self.inputbutton, SIGNAL("clicked()"), self.inputbutton_clicked)
        self.connect(self, SIGNAL("mitm_received"), self.update_textreceived)
        self.connect(self, SIGNAL("mitm_sent"), self.update_textsent)
        self.connect(self, SIGNAL("kernel_sent"), self.update_textsent)
        self.connect(self, SIGNAL("kernel_received"), self.update_textreceived)
        self.connect(self, SIGNAL("gratuitous_received"), self.update_textreceived)
        
    def add_connection_item(self, localip, localport, remoteip, remoteport):
        ''' Method that update the list of existing connections in the gui interface. (call by the TCPProtocol modified).
        '''
        if localip == self.ip:
            s = "%s:%s -> %s:%s" %(localip, localport, remoteip, remoteport)
        else:
            s = "%s:%s -> %s:%s" %(remoteip, remoteport, localip, localport)
        if len(self.connectionlist.findItems(s, Qt.MatchExactly)) == 0:
            self.connectionlist.addItem(s)
        
    def listenbutton_clicked(self):
        ''' Triggered when the user click on hook, or unhook button and do the appropriate action.
        If the user unhook a connection while it is not stopped, the connecions will likely crash because
        of de-synchronisation.
        '''
        if self.hooked:
            print("Stop hooking (can cause the connection to crash)")
            self.inputbutton.setEnabled(False)
            self.inputtext.setEnabled(False)
            self.connectionlist.setEnabled(True)
            self.listenbutton.setText("Hook")
            self.unhook_all() #Remove all the active nfqueues to stop hooking
            self.hooked = False
        else:
            print("Start Hooking")
            self.inputbutton.setEnabled(True)
            self.inputtext.setEnabled(True)
            self.connectionlist.setEnabled(False)
            self.textreceived.clear()
            self.textsent.clear()
            self.listenbutton.setText("Unhook")
    
            #Create the hacked session with the informations of the selected connection
            self.session = SessionMITM(self.interface, self) #Create the session
            self.session.register_lower_layer("default", self.tcpp) #Register it on the stack
            self.app = MITMApplication(self) #Create the MITM app and link it to the session
            self.session.register_layer(self.app)
            self.session.switch_state(State_ESTABLISHED(self.session)) #Put directly the session in ESTABLISHED
            
            #Create all the nfqueue and link them to the tcp session modified
            elts = self.connectionlist.selectedItems()
            if len(elts) != 1:
                QMessageBox.warning(self, "Warning", "A connection (only) should be selected", buttons=QMessageBox.Ok, defaultButton=QMessageBox.NoButton)
                print("One connection (only) should be selected")
                return
            else:
                s = elts[0].text() #Retrieve the selected connections and recover infos about it
                src, _, dst = s.split(" ")
                ipsrc, portsrc = src.split(":")
                ipdst, portdst = dst.split(":")
                
                self.ruleo = "-p tcp -s %s --sport %s -d %s --dport %s" %(ipsrc, portsrc, ipdst, portdst)
                self.qmo = NFQueueManager() #Create a NfqueueManager to deal with outgoing packets
                self.qmo.add_queue_rule("OUTPUT", self.ruleo , 11) #Add a nfqueue rule to the firewall
                self.qmo.run_queue(self.session.outgoing_nfqueue_packet, 11) #Start listening on the queue with the right handler
                
                self.rulei = "-p tcp -s %s --sport %s -d %s --dport %s" %(ipdst, portdst, ipsrc, portsrc)
                self.qmi = NFQueueManager() #Idem for incoming packets
                self.qmi.add_queue_rule("INPUT", self.rulei, 12)
                self.qmi.run_queue(self.session.incoming_nfqueue_packet, 12)
                self.hooked = True
        
    def unhook_all(self):
        ''' Remove the two added rules to stop catching kernel throughput and stop clean the whole. '''
        if self.hooked:
            self.qmo.remove_queue_rule("OUTPUT", self.ruleo, 11)
            self.qmi.remove_queue_rule("INPUT", self.rulei, 12)
            self.qmo.stopall()
            self.qmi.stopall()
    
    def inputbutton_clicked(self):
        ''' Function called to send data to server (without kernel knowledge) '''
        print("Input button clicked")
        tosend = str(self.inputtext.toPlainText())
        self.inputtext.clear()
        self.app.send_packet(tosend)
    
    def kernel_data_sent(self, data):
        print("Kernel Data sent: "+repr(data))
        self.emit(SIGNAL("kernel_sent"), "blue", data)
        #self.textsent.insertHtml('<font color=\"blue\">'+re.sub("\n","<br/>",data)+'</font>')

    def mitm_data_sent(self, data):
        print("MITM Data sent: "+repr(data))
        self.emit(SIGNAL("mitm_sent"), "red", data)
        #self.textsent.insertHtml('<font color=\"red\">'+re.sub("\n","<br/>",data)+'</font>')

    def kernel_data_received(self, data):
        print("For kernel received: "+repr(data))
        self.emit(SIGNAL("kernel_received"), "blue", data)
        #self.textreceived.insertHtml('<font color=\"blue\">'+re.sub("\n","<br/>",data)+'</font>')

    def mitm_data_received(self, data):
        print("MITM data received: "+repr(data))
        self.emit(SIGNAL("mitm_received"), "red", data)
        #self.textreceived.insertHtml('<font color=\"red\">'+re.sub("\n","<br/>",data)+'</font>')

    def gratuitous_data_received(self, data):
        print("Gratuitous Data: "+repr(data))
        self.emit(SIGNAL("gratuitous_received"), "black", data)
        #self.textreceived.insertHtml('<font color=\"black\">'+re.sub("\n","<br/>",data)+'</font>')
    
    def update_textreceived(self, color, text):
        self.textreceived.insertHtml('<font color=\"'+color+'\">'+re.sub("\n","<br/>",text)+'</font>')

    def update_textsent(self, color, text):
        self.textsent.insertHtml('<font color=\"'+color+'\">'+re.sub("\n","<br/>",text)+'</font>')
    
    def stop(self):
        self.unhook_all()
        self.ethp.stop()

if __name__ == "__main__":

    app = QApplication(sys.argv) #Create the Qt Application
    app.setApplicationName("MITM")
    win = MyWindowMITM() #Instanciate the window

    win.show()
    app.exec_() #Start the app
    
    print('Closing..')
    win.stop()
