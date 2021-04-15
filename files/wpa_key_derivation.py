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
from scapy.contrib.wpa_eapol import WPA_key
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

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 


# Below here are the seven values that we're about to dynamicaly extract from the capture file

# get info from first association request (ssid, APMac, ClientMAC)
def getAssocReqInfo(packets):
    for p in packets:
        if p.haslayer(Dot11): 
            if p.type == 0 and p.subtype == 0 :
                ar_ssid = p.info.decode('ascii')
                ar_APmac = a2b_hex(p.addr1.replace(':', ''))
                ar_Clientmac = a2b_hex(p.addr2.replace(':', ''))
                return ar_ssid, ar_APmac, ar_Clientmac

# get handshake messages
def getHandshakeMessages(packets):
    messages = []
    for p in packets:
        #AP to STA (handshake#1 and handshake#3)
        if p.haslayer(WPA_key):
            messages.append(p)
        #STA to AP (handshake#2 and handshake#4)
        if p.type == 0 and p.subtype == 0 and p.proto == 1:
            messages.append(p)

        if len(messages) == 4:
            return messages

def getNouncesAndMic(handshake):
    fromPacket_ANounce = handshake[0].nonce
    #FROM: https://stackoverflow.com/questions/27172789/how-to-extract-raw-of-tcp-packet-using-scapy
    fromPacket_SNounce = raw(handshake[1])[65:(65+32)]
    # This is the MIC contained in the 4th frame of the 4-way handshake
    fromPacket_mic = b2a_hex(raw(handshake[3])[129:-2])
    
    return fromPacket_ANounce, fromPacket_SNounce, fromPacket_mic

def getDataFromPacket(packet):
    return raw(packet)[48:129]


def main():
    # Important parameters for key derivation - Those two aren't picked from the .cap file
    passPhrase  = "actuelle"
    A           = "Pairwise key expansion" #this string is used in the pseudo-random function
    #Association Request Info
    ssid, APmac, Clientmac = getAssocReqInfo(wpa)
    #Handshake
    handshake = getHandshakeMessages(wpa)
    if len(handshake) != 4:
        print("Incomplete handshake. Quitting...")
        exit()
    # Authenticator and Supplicant Nonces, MIC
    ANonce, SNonce, mic = getNouncesAndMic(handshake)

    
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    # End Set to 0 based on the "Quelques éléments à considérer" :D
    data = getDataFromPacket(handshake[3]) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    print ("\n\nValues used to derivate keys")
    print ("============================")
    print ("Passphrase: ",passPhrase,"\n")
    print ("SSID: ",ssid,"\n")
    print ("AP Mac: ",b2a_hex(APmac),"\n")
    print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
    print ("AP Nonce: ",b2a_hex(ANonce),"\n")
    print ("Client Nonce: ",b2a_hex(SNonce),"\n")


    # Nothing to change regarding how B is computed -- No changes overall below
    B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

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

if __name__ == "__main__":
    main()