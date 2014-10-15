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

from scapy_io import ScapyIO
from scapy.all import Ether, ARP, conf, IP

from pystack.layers.layer import Layer


class EthernetProtocol(Layer):
    """
    This class provides all the functionalities to accomplish
    the layer 2 routing. When a packet is received from an upper layer
    this class basically look up in the host routing table to get the ip
    to send the packet to and if the mac address is not found trigger an 
    ARP request. It also maintain a pool of packet for which the destination
    MAC address is unknown until an ARP reply is received.
    """
    
    name = "Ether"
    
    def __init__(self, interface=None):
        """
        Init takes the local interface in order to retrieve the local MAC.
        This method also instantiate an ScapyIO class. We do not use the normal
        lower/upper layer system because in this case no any other lower layer
        is suitable other than ScapyIO.
        """
        Layer.__init__(self)
        self.io = ScapyIO(interface)
        self.io.register_handler(self)
        self.addr = ARP().hwsrc
        self.packet_pool = [] #Packet will be stored as a tuple (packet, timestamp)
    
    def packet_received(self, packet, **kwargs):
        """
        Decapsulate the packet as the Layer would have done except that if
        the packet is an IP packet this method update the ARP cache with ip and mac
        """
        name = packet.payload.name
        target = self.upperLayers.get(name, self.upperLayers["default"])
        kwargs["Ether"] = packet.fields
        if name == "IP":
            if self.upperLayers.has_key("ARP"):
                self.upperLayers["ARP"].update_cache(packet.payload.src, packet.src)
        target.packet_received(packet.payload, **kwargs)
    
    def transfer_packet(self, packet):
        """
        Rewrite transfer to use scapy_io because ethernet is the lowest layer.
        So in this case call the send method of Scapy
        """
        self.io.send(packet)
        
    def send_packet(self, packet, **kwargs):
        """
        When a packet is received from an upper layer try to route it. If
        the method return something call forge and transfert it (to scapyio)
        """
        args = self._route_packet(packet, **kwargs)
        if args:
            self.transfer_packet(self.forge_packet(packet, **args["Ether"]))
    
    def _route_packet(self, packet, **kwargs):
        """
        Basically change dst mac if needed in order to forge the ethernet packet.
        If destination MAC is not found an ARP request is triggered in the ARP layer
        and the packet put in a list while no ARP reply has been received.
        """
        if not kwargs.has_key("Ether"):
            kwargs["Ether"] = {}
            
        if isinstance(packet, ARP):  #If the packet is an ARP use the address defined in ARP headers
            kwargs["Ether"]["dst"] = packet.hwdst
            
        elif isinstance(packet, IP):
            dstIP = packet.dst
            try:
                iff, _, gw = conf.route.route(dstIP)
                #Get the right routing row for the given IP automaticaly no need to parse the routing table..
            except AttributeError:
                return None
            
            if gw != "0.0.0.0":  #If the host to send is different from the ip itself
                ipaddr = gw  #Use the gateway ip to do the routing (so gateway MAC)
            else:
                ipaddr = dstIP  #Otherwise use directly the IP of dest
            
            #TODO: Deal better with interface and why not sending trame on this interface instead of always the same one ?
            if iff == "lo":
                mac = "ff:ff:ff:ff:ff:ff"
            else:
                if self.upperLayers.has_key("ARP"):  #Check that ARP handler is registered in upper layer
                    mac = self.upperLayers["ARP"].get_mac(ipaddr)
                    #get_mac look up in the ARP table to return the MAC associated with the IP return None otherwise
                    if not mac:  #Nothing was returned
                        #print("Mac not found for "+ ipaddr)
                        self.packet_pool.append((packet, time.time()))  #Put the packet in the pool with a timestamp
                        self.upperLayers["ARP"].send_arp_request(ipaddr)  #Because nothing was found do an ARP request
                        return None
                else:
                    print("No ARP Layer registered to retrieve MAC")
                    return None
    
            kwargs["Ether"]["dst"] = mac  #Return args that will be sent to forge_packet
        return kwargs
    
    def forge_packet(self, packet, **kwargs):
        """ Forge the Ethernet packet using the given kwargs and the given packet"""
        return Ether(**kwargs)/packet
    
    def route_update(self, ip):
        """
        Method called by arp layer when receive an arp reply (is_at)
        Loop through all packets if the newly resolved MAC match dst of on of
        them complete the packet and send it.
        """
        updated_packet = []
        for p, _ in self.packet_pool:
            _, _, gw = conf.route.route(p.dst)  #Try to reroute each packets
            if gw == "0.0.0.0":
                gw = ip
            if gw == ip:
                mac = self.upperLayers["ARP"].get_mac(gw)
                #The ARP cache has been updated so a packet dst IP may be resolved into a MAC.
                if mac:  #If a mac was returned for the packet
                    #print("Packet match ARP reply: ",p)
                    completedpacket = self.forge_packet(p, dst=mac)
                    self.transfer_packet(completedpacket)
                    updated_packet.append(p)
        now = time.time()
        self.packet_pool = [x for x in self.packet_pool if now < x[1] + 5 and x[0] not in updated_packet] #Remove entries older than 5 seconds
        
    def start_listening(self, doreactor=True):
        """
        Because Ethernet have directly the ScapyIO as a class attribute it should
        interface ScapyIO methods. This method should be called to start listening
        on the socket using the appropriate method (twisted reactor or threads)
        """
        self.io.start_listening(doreactor)
    
    def stop(self):
        """Call the stop method of ScapyIO"""
        self.io.stop_listening()