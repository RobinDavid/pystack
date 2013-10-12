#!/usr/bin/env python

from distutils.core import setup

import os
#os.chdir("..")
#print os.listdir(os.getcwd())

setup(name='pystack',
    version='1.0.0',
    description='Python TCP/IP stack crafting tool',
    author='Robin David',
    author_email='dev.robin.david@gmail.com',
    url='https://www.github.com/RobinDavid/pystack/',
    packages_dir={'pystack','pystack'},
    packages=['pystack','pystack.layers'],
    classifiers=[
        "Programming Language :: Python",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Topic :: System :: Networking",
    ]
     )
