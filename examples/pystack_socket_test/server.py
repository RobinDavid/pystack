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

import pystack.pystack_socket as socket


HOST = '192.168.0.21'    # The remote host
#HOST = "www.google.fr"


PORT = 7777              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(("localhost",PORT))
s.listen(2)
cli, addr = s.accept()

print(addr)


#print("--")

while True:
    data = cli.recvfrom(2048)
    print data
    cli.send("OK")
    break
    if data.startswith("quit"):
        break
    else:
        print(len(data), data)

cli.close()
    
s.close()

s.stop() #To stop stack
