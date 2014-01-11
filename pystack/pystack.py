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
import time

from twisted.internet import reactor
from scapy.all import conf

from layers.ethernet import EthernetProtocol
from layers.ip import IPProtocol
from layers.arp import ARPProtocol
from layers.tcp import TCPProtocol
from layers.tcp_session import TCPSession
from layers.tcp_application import TCPApplication
from layers.udp import UDPProtocol
from layers.dns import DNSProtocol


class PyStack(object):
    """
    PyStack is the class that wrap all the layers together.
    It builds an entire stack linking all the layers. It implement
    the Singleton Pattern. So within a script or across modules if
    they all create a Pystack object only one will be instantiated 
    and all the connections and request will be handled by this one.
    It provides a method call register_tcp_application to attach a TCP
    application to the stack like a server or a client. Of course the 
    stack should be started with run to start listening packet and stop
    to stop listening packets.
    """
    
    instance = None  #Attributes for the singleton pattern
    instanciated = False
    running = False
    _session = TCPSession    
    
    def __new__(cls, *args, **kwargs):
        """ Override the new method to all the time return the same instance"""
        if not cls.instance:
            cls.instance = super(PyStack, cls).__new__(cls, *args, **kwargs)
        return cls.instance
    
    def __init__(self, iface=None):
        """
        Create the stack. An interface is needed in argument because
        various layer need it. Then buildstack is called to create the stack.
        """
        if not self.instanciated:
            if iface:
                self.interface = iface
            else:
                self.interface = conf.route.route("0.0.0.0")[0]
            self.eth = None
            self.tcp = None
            self.udp = None
            self.dns = None
            self._build_stack()
            self.instanciated = True
        
    def _build_stack(self):
        """
        Create all the layer and link them together. Of
        course other layer could be added if implemented.
        """
        #Layer 2
        self.eth = EthernetProtocol(self.interface)
        
        #Layer 3
        ip = IPProtocol()
        self.eth.register_layer(ip)
        arp = ARPProtocol(self.interface)
        self.eth.register_layer(arp)
        
        #Layer 4
        self.tcp = TCPProtocol()
        ip.register_layer(self.tcp)
        self.udp = UDPProtocol()
        ip.register_layer(self.udp)
        
        #Layer 7
        self.dns = DNSProtocol(self.interface)
        self.udp.register_layer(self.dns)
    
    def register_tcp_application(self, app):
        """
        Register a TCP application on the stack. So
        basically create a tcp session for the app and attach
        the TCPSession to the TCP layer.
        """
        
        #Layer 5
        tcpsession = self._session(self.interface)
        tcpsession.register_lower_layer("default", self.tcp)
        #self.tcp.register_layer(tcpsession)
        
        #Layer 6
        #Nothing for now 
        
        #Layer 7
        tcpsession.register_layer(app)

    def register_udp_application(self, app):
        """
        Register the given app as an UDP application.
        """
        app.register_lower_layer("default", self.udp)

    def run(self, doreactor=True):
        """
        Just call the start_listening of the Ethernet layer (which
        hold the ScapyIO). Except for reactor which normally catch SIGINT to
        stop the reactor. Here we catch the SIGINT oursleves and stop the reactor
        by changing a boolean (which is tested periodically)
        """
        if not self.running:
            if doreactor:
                import signal
                signal.signal(signal.SIGINT, self._siginthandler)
            self.running = True
            self.eth.start_listening(doreactor)
    
    def _siginthandler(self, signum, stackframe):
        """Handler for the SIGINT signal"""
        print("SIGINT : stop called, waiting to finish..")
        reactor.callInThread(self.stop) 
    
    def stop(self):
        """
        Stop will stop the stack. But to make it 'smartly' try for every
        connections of the tcp layer to call the close method if it exists.
        Then wait 5 seconds to be sure that all the connections have the time
        to stop and then stop the stack itself.
        """
        for conn in self.tcp.upperLayers.values():  #Try to close every opened sessions
            if hasattr(conn, "close"):
                if callable(getattr(conn,"close")):
                    print("call close for: ", conn.connectionID)
                    conn.close()
        time.sleep(5)  #To be sure all connections stops well..
        self.eth.stop()
        self.running = False

    def is_tcp_port_free(self, p):
        """Return either or not the port sent in parameter is free"""
        return self.tcp.is_port_free(p)
    
    def is_udp_port_free(self, p):
        """Return either or not the port sent in parameter is free"""
        return self.udp.is_port_free(p)

    def set_custom_session(self, sess):
        """ Method that allow to change the kind of session created when registering tcp application """
        self._session = sess


if __name__ == "__main__":
    stack = PyStack()
    
    conn = TCPApplication()
    stack.register_tcp_application(conn)
    stack.run(False)
    
    '''conn.bind(8888)
    conn.listen(2)
    
    s = conn.accept()
    '''
    print(conn.connect("perdu.com", 80))
    
    conn.send_packet("GET / HTTP/1.0\r\nUser-Agent: Wget/1.12 (linux-gnu)\r\nAccept: */*\r\nHost: perdu.com\r\nConnection: Keep-Alive\r\n\r\n")
    
    time.sleep(10)
    
    conn.close()
    
    stack.stop()