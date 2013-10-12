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
import random
from threading import Lock
import re

from scapy.all import get_if_addr, conf

from pystack.layers.layer import Layer
from pystack.kernel_filter import unblock_icmp_port_unreachable, block_icmp_port_unreachable
import transversal_layer_access

class UDPApplication(Layer):
    """
    UDP Application provides input output functionalities
    above the UDP layer. An UDP application is directly linked
    to the UDP layer (not like in TCP) because UDP is stateless
    """
    
    name = "Raw"
    
    def __init__(self, iface=None):
        """
        Init instantiate quite a lot of class attribute like
        ips, ports, datas etc..
        """
        Layer.__init__(self)
        self.data = []
        self.mutex = Lock()
        self.connectionID = None
        self.ipregex = re.compile("^(\d{1,3}.){3}.\d{1,3}$")
        self.interface = iface if iface else conf.route.route("0.0.0.0")[0]
        self.localIP = get_if_addr(self.interface)
        self.remoteIP = None
        self.localPort = random.randrange(0, (2**16) - 1)
        self.remotePort = None
    
    def packet_received(self, packet, **kwargs):
        """
        Add the received datas to the buffer data. The mutex
        prevent any improper read/write
        """
        self.mutex.acquire()
        self.data.append((kwargs["IP"]["dst"], kwargs["UDP"]["dport"], packet.load))
        self.mutex.release()
    
    def connect(self, ip, port):
        """
        In UDP connect is not really meaningfull. In this
        case it just means register an handler for the connection
        in the UDP layer
        """
        if not re.match(self.ipregex, ip): #Then this is a dn
            realip = transversal_layer_access["DNS"].nslookup(ip)
            if realip:
                self.remoteIP = realip
            else:
                raise Exception("[Errno -5] No address associated with hostname")
        else:
            self.remoteIP = ip
            
        self.remotePort = port
        self.connectionID = (self.localIP, self.localPort)
        self.lowerLayers['default'].register_upper_layer((self.localIP, self.localPort), self)

    def bind(self, port, app=None, fork=None):  #App and fork are just here to be generic with the tcp bind from the pysocket point of view
        """
        Bind like connect will register a handler in the UDP layer.
        But it will also prevent the host to send ICMP host port unreachable
        """
        self.localPort = port
        block_icmp_port_unreachable()  #block_outgoing_packets("udp", self.localIP, self.localPort, None, None)
        self.connectionID = (self.localIP, self.localPort)
        self.lowerLayers['default'].register_upper_layer(self.connectionID, self)

    def send_packet(self, packet, **kwargs):
        """
        Sending a packet to an host does not require any
        connection or any call to connect. So if a packet is the 
        first for a destination host. Associated rules are added in
        iptables. Then every fields are setup in order to call the 
        transfer it to the lowest layer
        """
        try:
            ip = self.remoteIP if self.remoteIP else kwargs["IP"]["dst"]
        except KeyError:
            raise Exception("[Errno 89] Destination address required")
        
        if not re.match(self.ipregex, ip): #Then this is a dn
            realip = transversal_layer_access["DNS"].nslookup(ip)
            if realip:
                ip = realip
            else:
                raise Exception("[Errno -5] No address associated with hostname")
        
        if not self.connectionID:
            block_icmp_port_unreachable()
            self.connectionID = (self.localIP, self.localPort)
            self.lowerLayers['default'].register_upper_layer(self.connectionID, self)
        
        if not kwargs.has_key("UDP"):
            kwargs["UDP"] = {}
        kwargs["UDP"]["sport"] = self.localPort
        kwargs["UDP"]["dport"] = self.remotePort if self.remotePort else kwargs["UDP"]["dport"]
        if not kwargs.has_key("IP"):
            kwargs["IP"] = {}        
        kwargs["IP"]["src"] = self.localIP
        kwargs["IP"]["dst"] = ip
        self.transfer_packet(packet, **kwargs)

    def close(self):
        """
        Close just unregister himself from the lower layer and
        remove rules from iptables
        """
        self.firstpacket = True
        unblock_icmp_port_unreachable()
        self.lowerLayers['default'].unregister_upper_layer(self.connectionID)

    def fetch_data(self, size=None):
        """fetch_data return the given number of bytes""" 
        res = self.fetch_data_from(size)
        if res:
            return res[2]
        else:
            return None
    
    def fetch_data_from(self, size=None):
        """
        fetch_data_from use the socket syntax and arguments. 
        It returns the datas associated to the given host. Because
        data in UDP is not a string this a list of string identified by
        the remote IP.
        """
        self.mutex.acquire()
        elt = None
        if len(self.data) != 0:
            s = ""
            if size:
                if size < len(self.data[0][2]):
                    elt = self.data[0]
                    s = self.data[0][2][:size]
                    self.data[0] = (self.data[0][0], self.data[0][1], self.data[0][2][size:])
                    elt = (elt[0], elt[1], s)
                else:
                    elt = self.data.pop(0)
            else:
                elt = self.data.pop(0)
        self.mutex.release()
        return elt
    
    #Methods added to help pysocket
    def get_conn_addr(self):
        """Return tuple of the remote IP remote port"""
        return (self.remoteIP, self.remotePort)
    
    def get_self_addr(self):
        """Return the tuple of the local ip local port"""
        return (self.localIP, self.localPort)