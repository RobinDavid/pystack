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
from threading import Lock

from scapy.all import Raw

from pystack.layers.layer import Layer


class TCPApplication(Layer):
    """
    TCPApplication provides the functionnalities for layer 7
    protocols. So there is just connection management and buffer
    reading/writing. Moreover for connection management it basically
    just call the ones from tcpsession which really do the stuff.
    """
    
    name = "Raw"
    
    def __init__(self):
        """
        Init Just init class attributes like data which will act as a buffer for received data.
        In addition a mutex is initialised so that data attribute can't be read and written in the same
        time and so avoid improper reading..
        """
        Layer.__init__(self)
        self.data = ""
        self.mutex = Lock()
        self.lastclient = None
    
    def packet_received(self, packet, **kwargs):
        """
        At this level a packet is Raw data so bytes. This
        method acquire the mutex add received datas and release the
        mutex.
        """
        self.mutex.acquire()
        self.lastclient = kwargs["id"]
        self.data += packet
        #print(packet)
        self.mutex.release()
        
    def connect(self, ip, port):
        """Just call the connect method of TCPSession layer"""
        return self.lowerLayers["default"].connect(ip, port)
    
    def listen(self, nb=0):
        """Just call the listen method of TCPSession layer"""
        self.lowerLayers["default"].listen(nb)
    
    def bind(self, port, app=None, newinstance=False):
        """
        Call the bind method of TCPSession with attributes. Be careful
        it is really important to understand what are attributes:
        
        - app: Should be a TCPApplication. So that all the clients that will
        connect the server will be attached to this tcpapplication
        If no app is provided the tcpapplication used is self !
        - newinstance: Define if all the clients should be linked on the same
        tcpapplication (attribute app) or if should be forked for each.
        """
        app = self if app is None else app
        self.lowerLayers["default"].bind(port, app, newinstance)
    
    def accept(self):
        """Call the TCPSession accept method """
        return self.lowerLayers["default"].accept()
    
    def close(self):
        """Call the close of the tcpsession"""
        return self.lowerLayers["default"].close()
    
    def transfer_packet(self, packet, **kwargs):
        """
        Override the transfertPacket method of Layer. Because
        for a server that use the same tcpapplication for every client
        the tcpsession to target is not the default me the right client.
        So check if a client was sent in kwargs if it is the case send the
        packet to the tcpsession of the client default otherwise
        """
        if kwargs.has_key("id"):
            id = kwargs.pop("id")
            if self.lowerLayers.has_key(id):
                self.lowerLayers[id].send_data(packet, **kwargs)
            else:
                self.lowerLayers["default"].send_data(packet, **kwargs)
        else:
            self.lowerLayers["default"].send_data(packet, **kwargs)  #Call send_data instead of send_packet
       
    def forge_packet(self, data):
        """ Forge the Raw packet using the datas given in parameter"""
        return Raw(load=data)
    
    def fetch_data(self, size=None):
        """
        Fetch_data acquire the mutex in order to pop data
        of the wanted size. If no size is specified return all
        the datas
        """
        self.mutex.acquire()
        s = ""
        if size:
            s = self.data[:size]
            self.data = self.data[size:]
        else:
            s = self.data
            self.data = ""
        self.mutex.release()
        return s
    
    def connection_made(self):
        """
        By default does nothing, but could be important
        in some layer 7 implementation like SSH ..
        """
        pass  #By default do nothing
    
    #Methods added to help pysocket
    def get_conn_addr(self):
        """ Return remote IP and remote Port"""
        return (self.lowerLayers["default"].remoteIP, self.lowerLayers["default"].remotePort)
    
    def get_self_addr(self):
        """Return our IP and the port associated"""
        return (self.lowerLayers["default"].localIP, self.lowerLayers["default"].localPort)
    
    def fetch_data_from(self, size=None):
        """Shortcut for the pysocket module """
        inf = self.get_conn_addr()
        return (inf[0], inf[1], self.fetch_data(size))
    
    #Method added to facilitate hack
    def hook_incoming(self, packet, **kwargs):
        """Method called by tcpsession when a packet is received. Can be overriden to apply operation on incoming packets"""
        pass
    
    def hook_outgoing(self, packet, **kwargs):
        """Method called by tcpsession just before a tcp packet is crafted and sent"""
        return packet, kwargs