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
from pystack.layers.tcp_application import TCPApplication
from twisted.web.server import Site
from twisted.web import static
from twisted.internet.abstract import FileDescriptor
from twisted.internet.abstract import _ConsumerMixin
import os

class WebServer(TCPApplication, _ConsumerMixin):
    ''' Simple TCPApplication that act as a simple HTTP server '''
    disconnecting = False #Required by twisted
    connected = True
    disconnected = False
    
    def __init__(self):
        TCPApplication.__init__(self)
        _ConsumerMixin.__init__(self)
        self.app = Site(static.File(os.path.abspath("./stegano/sitetest"))).buildProtocol("test") #Serve the given folder
        self.app.transport = self #Because we define self as transport we have to implement function normally called by twisted for a transport class
    
    def packet_received(self, packet, **kwargs): #Overwrite TCPApplication packet_received to call the dataReceived of twisted
        self.lastclient = kwargs["id"]
        try:
            print("---- Request received ----\n"+packet+"\n------------")
            self.app.dataReceived(packet)#TODO: A chaque fois qu'on fait un read write s'assurer que la connection existe toujours etc..
        except Exception, e:
            print("Something is wrong in the request:"+ str(e))
    
    def write(self, data):
        print "---- Data to send ----\n"+data+"\n------------"
        while len(data) > 0:
            x = data[0:1000]
            data = data[1000:]
            #self.send_data(x)
            self.send_packet(x, **{"id":self.lastclient}) #Overwrite method write of twisted to call our own method (send_packet).
    
    def getPeer(self): #Methods mandatory for a _ConsumerMixin
        class X:
            host = "myHost"
            port = "myPort"
        return X()

    def getHost(self):
        return self.getPeer()
    
    def writeSequence(self, iovec):
        self.write("".join(iovec))

    def loseConnection(self):
        pass
        
    def getvalue(self):
        pass

if __name__ =="__main__":
    from pystack.pystack import PyStack
    stack = PyStack("eth0") #Create a stack
    
    webserver = WebServer() #Create an instance of the TCPApplication
    stack.register_tcp_application(webserver)
    
    webserver.bind(80, app=webserver, newinstance=True)
    webserver.listen(5)
    
    stack.run(doreactor=True) #Run the stack
    
    '''
    #---- Solution where we create our stack by hand ----
    from pystack.layers.ethernet import EthernetProtocol
    from pystack.layers.ip import IPProtocol
    from pystack.layers.arp import ARPProtocol
    from pystack.layers.tcp import TCPProtocol
    from pystack.layers.tcp_session import TCPSession
    interface = "wlan0"
    eth = EthernetProtocol(interface)
    ip = IPProtocol()
    eth.register_layer(ip) #Enregistre aussi eth comme defaut pour ip
    arp = ARPProtocol(interface)
    eth.register_layer(arp)
    tcp = TCPProtocol()
    ip.register_layer(tcp)
    
    session = TCPSession(interface)
    tcp.register_layer(session)
    webserver = WebServer()
    session.register_layer(webserver)
    
    webserver.bind(80, app=webserver, newinstance=True) #Need to create new Webserver instance for each client otherwise I don't know why the twisted background fail after the second client (probably due to the fact it is really tricky)
    #app is the the tcp application were all clients will be bind
    #newinstance decide either or not we create a new app for every client or if we redirect them on the same
    
    webserver.listen(2)
    
    eth.start_listening(doreactor=True)
    #Use the reactor system so the program hook on this call
    #-------------------------------------------------------
    '''