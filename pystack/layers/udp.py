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

from scapy.all import UDP

from pystack.layers.layer import Layer


class UDPProtocol(Layer):
    """
    UDP Protocol provides basic functions of UDP. It
    allow to send and receive UDP packet
    """
    
    name = "UDP"
    
    def __init__(self):
        """
        Just call the layer init and give to the layer 
        the appropriate name (UDP)
        """
        Layer.__init__(self)
        #self.register_upper_layer("default", layer)
    
    def packet_received(self, packet, **kwargs):
        """
        When an UDP packet is received it is directly
        forwarded to the associated application if it exists.
        """
        key = (kwargs["IP"]["dst"], packet.dport)
        kwargs["UDP"] = packet.fields
        target = self.upperLayers.get(key, None)  #Or return the default and for each send reset (in case of full hook)
        if target:
            #kwargs["dport"] = packet.dport
            target.packet_received(packet.payload, **kwargs)
        else:
            target = self.upperLayers.get(packet.payload.name, None)
            if target:
                #kwargs["dport"] = packet.dport
                target.packet_received(packet.payload, **kwargs)
        
    def send_packet(self, packet, **kwargs):
        """
        Like in TCP send_packet call forge but without src and
        dst which are IP123 fields.
        """
        if not kwargs.has_key("UDP"):
            kwargs["UDP"] = {}
        self.transfer_packet(self.forge_packet(packet, **kwargs["UDP"]), **kwargs)
    
    def forge_packet(self, packet, **kwargs):
        """Forge the packet with or without payload"""
        if packet:
            return UDP(**kwargs)/packet
        else:
            return UDP(**kwargs)
    '''
    def forward_dns_request(self, name):
        """
        This method just forward the DNS request
        from the ip layer to the DNS layer
        """
        if self.upperLayers.get("DNS"):
            self.upperLayers["DNS"].send_dns_request(name)
        else:
            print("There is no DNS layer registered")
            
    def forward_dns_update(self, dn, ip):
        """
        Forward a DNS update from the DNS layer to
        the ip layer
        """
        self.lowerLayers["default"].dns_update(dn, ip)
    '''   
    def is_port_free(self, p):
        """Return either or not a port the given port is free"""
        for (_, port) in self.upperLayers.items():
            if p == port:
                return False
        return True