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

from scapy.all import ARP, ETHER_BROADCAST, get_if_addr

from pystack.layers.layer import Layer


class ARPProtocol(Layer):
    """
    Provides the basic functionalities provided by the
    ARP Protocol. It implements Layer. It keeps an ARP cache
    which is updated when an ARP reply is received. It also provides
    methods to do ARP request.
    """
    
    name = "ARP"
    
    def __init__(self, iface):
        """
        Takes the interface in argument to be able to distinguish
        the local MAC from others. The arp_cache is also instantiated empty.
        """
        Layer.__init__(self)
        self.arp_cache = {}
        self.hwaddr = ARP().hwsrc
        self.ip = get_if_addr(iface)
    
    def get_mac(self, ip):
        """
        Return the MAC address associated with the given IP if present.
        Otherwise it returns None.
        """
        if self.arp_cache.has_key(ip):
            return self.arp_cache.get(ip)
        else:
            return None
    
    def send_arp_request(self, ip):
        """Send an ARP request on the broadcast for the requested IP"""
        arprequest = ARP(op=ARP.who_has, pdst=ip, hwdst=ETHER_BROADCAST)
        self.transfer_packet(arprequest)
    
    def packet_received(self, packet, **kwargs):
        """
        Deal with an ARP packet received. If this is a reply
        (is_at) update the cache and call route_update that will
        flush potential packet waiting for MAC resolution. If the
        packet is a request (who_has) and for our MAC reply.
        """
        if packet.op == packet.is_at:
            self.update_cache(packet.psrc, packet.hwsrc)
            self.lowerLayers["default"].route_update(packet.psrc)
            
        elif packet.op == packet.who_has and packet.pdst == self.ip:
            reply = ARP(op=ARP.is_at, hwsrc=self.hwaddr, psrc=self.ip, hwdst=packet.hwsrc, pdst=packet.psrc)
            self.transfer_packet(reply, Ether={"dst":packet.hwsrc})
    
    def update_cache(self, ip, addr):
        """Update the cache with the given IP and MAC."""
        self.arp_cache[ip] = addr