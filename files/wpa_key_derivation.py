#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from scapy.contrib.wpa_eapol import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import os 
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




# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("files/wpa_handshake.cap") 

 
handshake = []

# capture handshake and ssid name and mac of AP and Client
for frame in wpa:
    # first get ssid name and mac
    # find beacon frame (type 0 (management) , subtype 8 (Beacon))
    if frame.type == 0 and frame.subtype == 8:  
        ssid = frame.info.decode("utf-8")
        APmac = a2b_hex(frame.addr2.replace(':',''))
    # find authentication frame (type 0 ,subtype 11 )
    if frame.type == 0 and frame.subtype == 11 and a2b_hex(frame.addr2.replace(':', '')) == APmac :
            # get client mac 
            Clientmac = a2b_hex(frame.addr1.replace(':', ''))  
    # 4-way handshake 
    # layer WPA_key give frame 1 and 3 and proto == 1 (protocol EAPOL) give frame 2 and 4
    if frame.haslayer(EAPOL) or frame.type == 0 and frame.subtype == 0 and frame.proto == 1:
        handshake.append(frame)
        
# get Nonce and MIC
if(len(handshake) != 4):
    print("bad handshake or too many handshake in pcap")
    exit()

ANonce = handshake[0][EAPOL].nonce
# for some reason this packet has no EAPOL layer to get nonce from (both field exist in wireshark)
SNonce = raw(handshake[1])[65:97]
# same as above, in wireshark it's from 129 to the end without last two bytes 
mic_to_test = raw(handshake[3])[129:-2]
# parameters that can't be obtained via the pcap file 
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
