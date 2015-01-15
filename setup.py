#!/usr/bin/env python

from distutils.core import setup
setup(
    name='flocksync',
    description='Peer to peer app synchronization protocol',
    url='https://github.com/jbruestle/flock',
    license='MIT',
    author='Jeremy Bruestle',
    author_email='jeremy.bruestle@gmail.com',
    version='0.2.1',
    packages=['flock'],
    scripts=['scripts/flock'],
    install_requires=[
        'bintrees', 
        'pycrypto',
        'bencode',
        'miniupnpc',
        'netifaces',
        'simplejson',
        'ipaddr',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking',
    ],
)
