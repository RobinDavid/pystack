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

from pystack.layers.ethernet import EthernetProtocol
from pystack.layers.layer import Layer
from pystack.layers.ip import IPProtocol
from pystack.layers.arp import ARPProtocol
from pystack.layers.tcp import TCPProtocol
from pystack.layers.tcp_session import TCPSession
from pystack.layers.tcp_application import TCPApplication
from twisted.internet import reactor
from scapy.all import IP

'''
    Simple exemple that show how to create a stack by hand.
'''


class Scream(Layer):
    
    def packet_received(self, packet):
        print("Scream: "+ packet.payload.name)

interface = "eth0"

#Layer 2
eth = EthernetProtocol(interface)

#Layer 3
ip = IPProtocol()
eth.register_layer(ip) #Enregistre aussi eth comme defaut pour ip
arp = ARPProtocol(interface)
eth.register_layer(arp)

#Layer 4
tcp = TCPProtocol()
ip.register_layer(tcp)

#Layer 5
tcpsession = TCPSession(interface)
tcp.register_layer(tcpsession)

#Layer 6
#Nothing for now 

#Layer 7
conn = TCPApplication()
tcpsession.register_layer(conn)
#conn.connect("192.168.1.48",7777)
conn.bind(7777)
#conn.send_packet("Hello world !")

#packet = IP(dst="192.168.1.48")
#ip.send_packet(packet)
'''
def test():
    global ip
    packet = IP(dst="192.168.1.48")
    ip.send_packet(packet)

reactor.callWhenRunning(test)

reactor.run()
'''
eth.start_listening(False)