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

try :
    import transversal_layer_access
except ImportError:
    import sys
    sys.modules["transversal_layer_access"] = {} #With this trick only Raw entry is not consistent
    import transversal_layer_access

class Layer(object):
    """
    Mother class for all the layers(protocols) of the stack.
    It provides many methods to register an upper or lower layer.
    Moreover it provides methods that should be overriden by
    children layers according to theirs behavior.
    By the way Layer is an "abstract" class it should not be instanciated
    """
    
    name = ""
    
    def __init__(self):
        """
        Init register a Default instance as default upperLayer for
        unknown packets (but does nothing)
        """
        self.lowerLayers = {}
        self.upperLayers = {}
        self.register_upper_layer("default", Default())
        if self.name != "Raw": #Trick to do not register all tcp session, application even though they extends Layer(and we stay generic)
            transversal_layer_access[self.name] = self #Used to allow every layer access each other
        
    def register_upper_layer(self, name, layer):
        """
        Add the given layer into the upperlayers dict
        using the given name as key
        """
        self.upperLayers[name] = layer
        
    def register_lower_layer(self, name, layer):
        """Register the given layer in the lowerlayers dict
        using the given name as key
        """
        self.lowerLayers[name] = layer
    
    def register_layer_full(self, name, layer):
        """
        Shortcut method to register the given layer as upperlayer
        and register self as the default lowerlayer for layer.
        This can not be used in all cases
        """
        self.register_upper_layer(name, layer)
        layer.register_lower_layer("default", self)
    
    def register_layer(self, layer):
        """Shortcut for register_layer_full using the layer.name as key"""
        self.register_layer_full(layer.name, layer)
    
    def unregister_upper_layer(self, name):
        """
        Remove the the layer referenced by the name in upperlayer.
        The exception is catched to prevent to make the program crash
        """
        try:
            self.upperLayers.pop(name)
        except KeyError:
            print("Cannot delete, "+ str(name))
    
    def transfer_packet(self, packet, **kwargs):
        """
        Define the default behavior when a packet should be transfered to the lower layer.
        The default behavior is to call the send_packet of the default lowerlayer. This method
        can be overriden by child layers
        """
        self.lowerLayers["default"].send_packet(packet, **kwargs)
    
    def packet_received(self, packet, **kwargs):
        """
        Define the default behavior when a packet is received. By default decapsulate the packet
        and send the payload to the upperlayer referenced by the payload name (TCP, IP ..)
        """
        target = self.upperLayers.get(packet.payload.name, self.upperLayers["default"])  #Get the handler name, default instead
        kwargs[packet.name] = packet.fields
        target.packet_received(packet.payload, **kwargs)  #Call packet_received of the handler with the payload
    
    def send_packet(self, packet, **kwargs):
        """
        By default when calling send_packet it forge the packet calling
        forge_packet and forward it to the lower layer calling transfer_packet
        """
        self.transfer_packet(self.forge_packet(packet), **kwargs)
    
    def forge_packet(self, packet, **kwargs):
        """By default does nothing but should be overriden by child class"""
        pass


class Default():
    """
    Default implements Layer. It just override packet_received
    to do nothing. Class called when there is not handler for the packet
    """
    def __init__(self):
        """Does nothing"""
        pass
    
    def packet_received(self, packet, **kwargs):
        """Does nothing. Is called for every packet that does not have any handler"""
        pass  #print("Unsupported: ",packet.payload.name, repr(packet))