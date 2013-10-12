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
import random
import time

from scapy.all import DNS, DNSQR

from pystack.layers.udp_application import UDPApplication


class DNSProtocol(UDPApplication):
    """
    Provide basic DNS implementation. It can
    send DNS request to resolve an hostname, and process
    replies sent by the server. The server used is a server of 
    OpenDNS
    """
    
    name = "DNS"
    
    def __init__(self, iface=None):
        """
        Instantiate default, dns server, and ids which keeps the IDs
        of the pending DNS requests
        """
        UDPApplication.__init__(self, iface)
        self.ipregex = re.compile("^(\d{1,3}.){3}.\d{1,3}$")
        self.opendnsip = "208.67.222.222"
        self.ids = {}
    
    def packet_received(self, packet, **kwargs):
        """
        Process DNS packets. But process only incoming answers
        for which we made a request
        """
        if kwargs["IP"]["src"] != self.localIP:  #Skip all outgoing DNS packets
            
            if packet.an:
                for answer in packet.an:
                    if answer.type == 1 and re.match(self.ipregex, answer.rdata) and self.ids.has_key(packet.id):  #1 is answer type
                        #self.ids.pop(packet.id)  #Remove the id of the request
                        #self.lowerLayers["default"].forward_dns_update(answer.rrname, answer.rdata)  #Advertise lower layer of the resolution so that it can flush packets waiting for DNS resolution.
                        self.ids[packet.id] = answer.rdata
                        self.close()  #Close (UDP layer will remove self as an upperlayer handler)

    def send_dns_request(self, name):
        """Craft and send a DNS request for the given name"""
        options = {}
        packet_id = random.randrange(0, 2**16 -1)  #Generate a random ID
        options["id"] = packet_id
        self.ids[packet_id] = None
        options["rd"] = 1
        options["qd"] = DNSQR(qname=name, qtype="A")
        self.send_packet(self.forge_packet(None, **options), IP={"dst":self.opendnsip}, UDP={"dport":53})
        return packet_id
    
    def nslookup(self, name):
        """Make a DNS request to resolve a domain name"""
        packet_id = self.send_dns_request(name)
        t = time.time()
        while t+5 > time.time():
            if self.ids[packet_id]:
                return self.ids.pop(packet_id)
            else:
                time.sleep(0.1)
        self.ids.pop(packet_id)
        return None
    
    def forge_packet(self, packet=None, **fields):
        """Just forge the DNS packet with arguments sent in **field"""
        if packet:
            return DNS(**fields)/packet
        else:
            return DNS(**fields)
