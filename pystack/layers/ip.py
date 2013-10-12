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

import re
import time
import random

from scapy.all import IP, conf, fragment, TCP, ICMP, UDP
import StringIO

from pystack.layers.layer import Layer


class IPProtocol(Layer):
    """IPProtocol assure the routing at the layer 3 IP."""
    
    name = "IP"
    
    def __init__(self, method="last"):
        """Initialise the packet pool"""
        Layer.__init__(self)
        #self.domainCache = {}  #Key: DN value: ip
        #self.reversedomainCache = {}  #Key: ip, value: DN
        self.packet_pool = {}  #Index will be (ipsrc,ipdst,ipid) value : {'timestamp':XXXXX, 'chunk':[p1,p2..]}
        self.ipregex = re.compile("^(\d{1,3}.){3}.\d{1,3}$")
        self.interface = conf.iface  #or conf.route.route("0.0.0.0")
        self.MTU = 1480 #self._get_mtu_interface(self.interface) - 20 #Remove the 20 bytes of IP headers needed
        methods = ("first", "last", "bsd", "linux", "bsdright", "linux")  #last is also called rfc791
        self.protocols = {1:"ICMP", 6:"TCP", 17:"UDP"}
        if method not in methods:
            raise Exception("The fragment reassembly method is unknown")
        self.reassembly_method = getattr(self, "_"+method)
    
    def _get_mtu_interface(self, iface):
        """
        Return the MTU value of the given interface using datas stored in
        /sys/class/net/$iface/mtu
        """
        return int(open("/sys/class/net/"+iface+"/mtu", "r").read())

    
    def packet_received(self, packet, **kwargs):
        """
        Call the right handler but also add the source and destination IP as kwargs otherwise
        after decapsulation it will be lost and upper layers need to get it
        """
        target = self.upperLayers.get(packet.payload.name, self.upperLayers["default"])
        kwargs["IP"] = packet.fields
        id = (packet.src, packet.dst, packet.id)
        if self.packet_pool.has_key(id):
            if packet.flags == 1:  #MF
                self.packet_pool[id]["chunk"].append(packet)
                self.packet_pool[id]["timestamp"] = time.time()
            else:
                self.packet_pool[id]["chunk"].append(packet)  #Append the packet in order to reassemble them
                bytes_reassembled = self.reassembly_method(self.packet_pool[id]["chunk"])
                self.packet_pool.pop(id)
                #newpacket = globals()[self.protocols[packet.proto]](bytes_reassembled)
                proto = self.protocols[packet.proto]
                if proto == "TCP":
                    newpacket = TCP(bytes_reassembled)
                elif proto == "ICMP":
                    newpacket = ICMP(bytes_reassembled)
                elif proto == "UDP":
                    newpacket = UDP(bytes_reassembled)
                else:
                    raise Exception("Protocol unkown after reassembly")
                target = self.upperLayers.get(proto, self.upperLayers["default"])
                target.packet_received(newpacket, **kwargs)
        else:
            if packet.flags == 1:
                self.packet_pool[(packet.src, packet.dst, packet.id)] = {'timestamp': time.time(), "chunk" : [packet]}
            else:
                target.packet_received(packet.payload, **kwargs)
        
        now = time.time()
        for id in self.packet_pool.keys():
            if self.packet_pool[id]['timestamp']+30 < now:  #Timeout IPv4 fragment reassembly (30 or 60 seconds) (p.448)
                self.packet_pool.pop(id)
    
    def send_packet(self, packet, **kwargs):
        """
        If the destination is an IP just transfert it.
        If this is an DN try to get the IP otherwise put the packet in the
        pool and trigger a DNS request for the given DN
        """
        if not kwargs.has_key("IP"):
            kwargs["IP"] = {}
        if not kwargs["IP"].has_key("id"):
            kwargs["IP"]['id'] = random.randrange(1, 65535)
            
        p = self.forge_packet(packet, **kwargs["IP"])
        
        if len(p) > self.MTU:
            fragments = fragment(p, fragsize=self.MTU)
            for frag in fragments:
                self.transfer_packet(frag, **kwargs)
        else:
            self.transfer_packet(p, **kwargs)
        '''
        ipordn = kwargs["dst"]
        if re.match(self.ipregex, ipordn):
            self.transfer_packet(self.forge_packet(packet, **kwargs))
        else:
            if self.reversedomainCache.has_key(ipordn):  #If the ip of dn is already in the cache
                kwargs["dst"] = self.reversedomainCache.get(ipordn)
                self.transfer_packet(self.forge_packet(packet, **kwargs))
            elif self.upperLayers.has_key("UDP"):  #Check that upper layer has an UDP layer (otherwise there is no DNS)
                self.packet_pool.append((packet, kwargs))  #Pool the packet
                self.upperLayers["UDP"].forward_dns_request(ipordn)  #Trigger DNS request
            else:
                print("There is no UDP layer registered to do a DNS request")
         '''
               
    def forge_packet(self, packet, **kwargs):
        """Just forge the packet id the associated arguments"""
        return IP(**kwargs)/packet
    
    '''
    def dns_update(self, dn, ip):
        """
        This method handle a DNS update an try to resend packet
        that were waiting for a name resolution
        """
        if dn[-1:] == ".":  #Sometimes dns answer contain "." at the end of the domain so remove it
            dn = dn[:-1]
        self.domainCache[dn] = ip  #Update the both cache
        self.reversedomainCache[ip] = dn
        for p, args in self.packet_pool:
            if args["dst"] == dn:  #if dst match dn
                args["dst"] = ip  #Change dst to the right IP
                if p.name == "TCP":
                    block_outgoing_packets('tcp', None, None, ip, p.dport)  #cause as not been done before
                self.transfer_packet(self.forge_packet(p, **args))
                print("Packet pooled: ", dn, ip, p.dport, repr(p))
        self.packet_pool = []  #Flush packets even them those who have not been resolved
    '''
    
    def _first(self, fragments):
        """Refragmentation method call first. The first packet arrived overlap the others"""
        buffer = StringIO.StringIO()
        for frag in reversed(fragments):
            buffer.seek(frag.frag*8)
            buffer.write(frag.payload)
        return buffer.getvalue()
    
    def _last(self, fragments):
        """The last packet coming override others"""
        buffer = StringIO.StringIO()
        for frag in fragments:
            buffer.seek(frag.frag*8)
            buffer.write(frag.payload)
        return buffer.getvalue()
    
    def _bsdright(self, fragments):
        """Reassembly method called bsdright"""
        buffer = StringIO.StringIO()
        for frag in sorted(fragments, key=lambda x:x.frag):
            buffer.seek(frag.frag*8)
            buffer.write(frag.payload)
        return buffer.getvalue()
    
    def _bsd(self, fragments):
        """Reassembly method also called bsd"""
        buffer = StringIO.StringIO()
        for frag in reversed(sorted(fragments, key=lambda x:x[IP].frag)):
            buffer.seek(frag.frag*8)
            buffer.write(frag.payload)
        return buffer.getvalue()
    
    def _linux(self, fragments):
        """Reassembly method called Linux"""
        buffer = StringIO.StringIO()
        for frag in sorted(fragments, key=lambda x:x[IP].frag, reverse=True):
            buffer.seek(frag.frag*8)
            buffer.write(frag.payload)
        return buffer.getvalue()