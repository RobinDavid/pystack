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

from pystack.layers.layer import Layer
from pystack.layers.tcp import TCPProtocol

class TCPProtoModified(TCPProtocol):
    def __init__(self,win):
        Layer.__init__(self)
        self.win = win #Take the Qt window as attribute to be able to send it, newly detected connections 
        
    def packet_received(self, packet, **kwargs):
        self.win.add_connection_item(kwargs["IP"]["src"], packet.sport, kwargs["IP"]["dst"], packet.dport)
        TCPProtocol.packet_received(self, packet, **kwargs)