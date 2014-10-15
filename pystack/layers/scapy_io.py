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

from scapy.all import L2ListenSocket, sendp, MTU
from twisted.internet import base, reactor
from threading import Thread


class ScapyIO(base.BasePort):
    """
    SacpyIO play the role of interface with Input/Output functions
    of Scapy. So all the packets that are received and sent pass
    through here. To receive packet ScapyIO use a L2ListenSocket object.
    Then to read packets two methods are implemented, either twisted reactor
    add a reader on the socket or a thread that will loop reading packet in
    the socket. To send packet the sendp method is called
    """
    
    def __init__(self, interface=None):
        """
        ScapyIO extends BasePort, so this is easier with reader.
        It also create the L2ListenSocket but do not listen on it yet.
        """
        base.BasePort.__init__(self, reactor)
        self.interface = interface
        self.handler = []
        self.socket = L2ListenSocket(iface=self.interface, promisc=True)
        self.th = None
        self.stop = False
        
    def register_handler(self, handler):
        """
        Register an handler for the packet received. We can put multiples
        ones but in the classical case there will be one which is the Ethernet
        layer.
        """
        self.handler.append(handler)
        
    def start_listening(self, doreactor=True):
        """
        Start listening on the socket using the appropriate method.
        If reactor is choosen it adds a reader on the socket and create
        a callback that will be able to check with the user want to stop.
        Note that signalHandlers are disabled for the reactor.
        If not reactor is choosen then a thread is used and will be started
        enclosed in the _do_read_thread method.
        """
        if doreactor:
            reactor.addReader(self)
            reactor.callWhenRunning(self._reactor_callback)
            reactor.run(installSignalHandlers=0)
        else:
            self.th = Thread(target=self._do_read_thread)
            self.th.start()
        
    def _do_read_thread(self):
        """
        Read the socket endlessly and call the handler
        for each packet. But it check every loop than stop
        is not activated
        """
        while True:
            if self.stop:
                break
            packet = self.socket.recv(MTU)
            for h in self.handler:
                h.packet_received(packet)
    
    def fileno(self):
        """Needed for the reader"""
        return self.socket.ins.fileno()

    def doRead(self):
        """
        Method called when the reader read a packet
        in the socket. So basically forward it to the 
        handler(s)
        """
        packet = self.socket.recv(MTU)
        for h in self.handler:
            h.packet_received(packet)

    def send(self, packet):
        """Send the given packet without any kind of test"""
        sendp(packet, iface=self.interface, verbose=False)
    
    def stop_listening(self):
        """
        Just put the boolean to True. Then the reader
        or the thread will have to notice it. Note that
        it can take a while because with threads, the thread
        is blocked in the recv method until a packet is received
        """
        self.stop = True
        #Send malformed packet to unblock thread in recv (if needed)
    
    def _reactor_callback(self):
        """
        Callback function attached to the reader. All
        the read to check if stop is activated or not. If
        it is stop himself otherwise reschedule the callback
        in 1 second.
        """
        if self.stop:
            reactor.stop()
        else:
            reactor.callLater(1, self._reactor_callback)