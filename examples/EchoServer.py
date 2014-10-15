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
import sys

from pystack.layers.tcp_application import TCPApplication
from pystack.pystack import PyStack

class EchoServer(TCPApplication):
    def packet_received(self, packet, **kwargs): #Just overwrite packetreceived
        self.send_packet(packet, **kwargs) #Just call reply the same data received by calling send_packet
        
if __name__ =="__main__":
    stack = PyStack(iface=sys.argv[1] if len(sys.argv) > 1 else None) #Create the stack
    
    echoserver = EchoServer() #Instanciate the TCPApplication
    
    stack.register_tcp_application(echoserver) #Register the TCPApplication on the stack
    
    echoserver.bind(8888, echoserver, False) #Bind the TCPApplication to wait for connections
    #8888 is the port, echoserver means that for every client an echoserver application will be used and False means
    # that the echoserver instance will not be forked for every client so they will all by managed by the same instance
    # A shortcut would have simply been: echoserver.bind(5555) because by default new client are mapped on the same app without creating new instance
    echoserver.listen(5) #Listen 5 clients at max
    
    stack.run(doreactor=True) #stack.stop() called when Ctrl+C 
