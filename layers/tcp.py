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

from scapy.all import TCP

from pystack.layers.layer import Layer


class TCPProtocol(Layer):
    """
    TCPProtocol assure routing functions of
    the TCP protocol. It basically route packets to
    the right tcp session.
    """
    
    name = "TCP"
    
    def __init__(self):
        """Just call Layer init method."""
        Layer.__init__(self)
        #self.register_upper_layer("default", layer)
    
    def packet_received(self, packet, **kwargs):
        """
        When a packet is received if upper layer contains an
        entry like (srcip,srcport,dstip,dstport) the packet is sent to
        it otherwise else check (dstip,dstport) if a server is registered.
        """
        key = (kwargs["IP"]["src"], packet.sport, kwargs["IP"]["dst"], packet.dport)
        kwargs["TCP"] = packet.fields
        target = self.upperLayers.get(key, None)  #Or return the default and for each send reset (in case of full hook)
        if target:
            target.packet_received(packet, **kwargs)  #Foward without decapsulating
        else:
            '''
            if kwargs.has_key("dn"):  #Maybe registered with domain name not ip
                key = (kwargs["dn"], packet.sport, kwargs["dstip"], packet.dport)
                target = self.upperLayers.get(key, None)  #Or return the default and for each send reset (in case of full hook)
                if target:
                    target.packet_received(packet, **kwargs)
                    return
            '''
            #Maybe a server is listen and the key is only ip:port
            key = (kwargs['IP']["dst"], packet.dport)
            target = self.upperLayers.get(key, None)  #Or return the default and for each send reset (in case of full hook)
            if target:
                target.packet_received(packet, **kwargs)
            else:
                pass  #The packet is not for us
        
    def send_packet(self, packet, **kwargs):
        """
        Call forge and ten call transfert packet.
        """
        self.transfer_packet(self.forge_packet(packet, **kwargs["TCP"]), **kwargs)
    
    def forge_packet(self, packet, **kwargs):
        """
        Forge the TCP packet with the given argument and the 
        payload if present
        """
        if packet:
            return TCP(**kwargs)/packet
        else:
            return TCP(**kwargs)
        
    def is_port_free(self, p):
        """
        Loop through all the connections to check that the
        given port is free. Note this method does not take in
        account real connection made by the kernel
        """ 
        for conn in self.upperLayers.items():
            if len(conn) == 4:
                if p == conn[3]:
                    return False
            else:
                if p == conn[1]:
                    return False
        return True