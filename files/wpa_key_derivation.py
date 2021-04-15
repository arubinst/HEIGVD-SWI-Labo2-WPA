#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein, Yann Lederrey, Laurent Scherer"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.contrib.wpa_eapol import WPA_key

"""
sources : 
  * https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/
  * Find the handshake packets: 
  https://scapy.readthedocs.io/en/latest/api/scapy.contrib.wpa_eapol.html
  #scapy.contrib.wpa_eapol.WPA_key
  * Association request layer packets with Scapy Dot11AssoReq: 
  https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html#scapy
  .layers.dot11.Dot11AssoReq
"""

from binascii import a2b_hex

from scapy.all import *
from scapy.layers.dot11 import Dot11AssoReq

from pbkdf2 import *


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the
    512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key,
                            A + str.encode(chr(0x00)) + B + str.encode(chr(i)),
                            hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def getAssociationRequestPackets(wpa):
    """
    return ssid, APmac, Clientmac
    """
    assoReqPkt = b''
    for p in wpa:
        if p.haslayer(Dot11AssoReq):
            assoReqPkt = p
            # break
    return assoReqPkt.info.decode(), \
           a2b_hex(assoReqPkt.addr1.replace(':', '')), \
           a2b_hex(assoReqPkt.addr2.replace(':', ''))


def getHandshake(wpa):
    """
    returns ANonce, SNonce, mic, data
    """
    handshake = []
    # we could brake once we have the full handshake (4 values) but it's so fast
    # that it doesn't matter.
    for p in wpa:
        # if it has that layer it's part of the handshake, cf. sources
        if p.haslayer(WPA_key):
            handshake.append(p.getlayer(WPA_key))
    # Authenticator and Supplicant Nonces
    mic_to_test = handshake[3].wpa_key_mic
    handshake[3].wpa_key_mic = 0
    data = bytes(handshake[3].underlayer)
    return handshake[0].nonce, handshake[1].nonce, mic_to_test, data


def printResultsKeyExpansion(pmk, ptk, mic):
    print("\nResults of the key expansion")
    print("=============================")
    print("PMK:\t\t", pmk.hex())
    print("PTK:\t\t", ptk.hex())
    print("KCK:\t\t", ptk[0:16].hex())
    print("KEK:\t\t", ptk[16:32].hex())
    print("TK:\t\t", ptk[32:48].hex())
    print("MICK:\t\t", ptk[48:64].hex())
    print("MIC:\t\t", mic.hexdigest())


if __name__ == '__main__':
    # Read capture file -- it contains beacon, authentication, associacion,
    # handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    ssid, APmac, Clientmac = getAssociationRequestPackets(wpa)
    ANonce, SNonce, mic_to_test, data = getHandshake(wpa)

    # Important parameters for key derivation - most of them can be obtained
    # from
    # the pcap file
    passPhrase = "actuelle"
    # this string is used in the pseudo-random function
    A = "Pairwise key expansion"

    B = min(APmac, Clientmac) \
        + max(APmac, Clientmac) \
        + min(ANonce, SNonce) \
        + max(ANonce, SNonce)  # used in pseudo-random function

    print("\n\nValues used to derivate keys")
    print("============================")
    print("Passphrase: \t", passPhrase)
    print("SSID: \t\t", ssid)
    print("AP Mac: \t", APmac.hex())
    print("CLient Mac: \t", Clientmac.hex())
    print("AP Nonce: \t", ANonce.hex())
    print("Client Nonce: \t", SNonce.hex())

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    ssid = str.encode(ssid)
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact,
    # KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    printResultsKeyExpansion(pmk, ptk, mic)
