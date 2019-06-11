# Tool maded in python by myself to encrypt your text.
# Options: Md5, Sha256, Sha512, Base64, Reverse Text, Caesar Cipher and Hexadecimal.
# By: yzkuxp
# Enjoy ^^

#!/usr/bin/env python
#coding: utf-8

import hashlib
from base64 import b64encode, b64decode
import codecs
import binascii
import re
from time import sleep
import sys
import string
import os
from platform import python_version

if sys.version_info[0] < 3:
    version = python_version()
    print("You are using python in version %s which is lower than python3 onward." %(version))
    print("Please run the tool with a version higher than python 3.x.x.")
    sleep(3)
    exit(1)

def Clear():
    os.system('cls')

def Blank():
    print("    ")

def Apresentation():
    Clear()
    print ("""
\t\t   ___________________________________________
\t\t  |                                           |
\t\t  |    ____  _     _           _         _    |
\t\t  |   |    \|_|___| |_ ___ ___| |_ ___ _| |   |
\t\t  |   |  |  | |_ -|  _| . |  _|  _| -_| . |   |
\t\t  |   |____/|_|___|_| |___|_| |_| |___|___|   |
\t\t  |                By: yzkuxp                 |
\t\t  |                                           |
\t\t  |___________________________________________|
    """)

def Md5Encrypt():
    Apresentation()
    stringMd5 = input("\nType the text you want to encrypt in Md5: ")
    ResultMd5 = hashlib.md5(stringMd5.encode())
    print ("Result: " + ResultMd5.hexdigest())
    Blank()
    sleep(1)
    redo = input("Do you want to do another encrypt in Md5?(y/N) ")
    if redo == "y" or redo =="Y":
        Md5Encrypt()
    else:
        Menu()

def Sha256Encrypt():
    Apresentation()
    stringSha256 = input("\nType the text you want to encrypt in Sha256: ")
    ResultSha256 = hashlib.sha256(stringSha256.encode())
    print("Result: " + ResultSha256.hexdigest())
    Blank()
    sleep(1)
    redo = input("Do you want to do another encrypt in Sha256?(y/N) ")
    if redo == "y" or redo =="Y":
        Sha256Encrypt()
    else:
        Menu()

def Sha512Encrypt():
    Apresentation()
    stringSha512 = input("\nType the text you want to encrypt in Sha512: ")
    ResultSha512 = hashlib.sha512(stringSha512.encode())
    print ("Result: " + ResultSha512.hexdigest())
    Blank()
    sleep(1)
    redo = input("Do you want to do another encrypt in Sha512?(s/N) ")
    if redo == "y" or redo =="Y":
        Sha512Encrypt()
    else:
        Menu()

def Base64Encrypt():
    Apresentation()
    stringBase64E = input("\nType the text you want to encrypt in Base64: ")
    ResultBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = ResultBase64E.decode('utf-8')
    print ("Result: " + decode)
    Blank()
    sleep(1)
    redo = input("Do you want to do another encrypt in Base64?(y/N) ")
    if redo == "y" or redo =="Y":
        Base64Encrypt()
    else:
        Menu()

def CipherCaesarEncrypt():
    Apresentation()
    messageE = input("\nType the text you want to encrypt in Caesar Cipher: ")
    cifraE = int(input("Type the key: "))
    print ("Result: ", end="")
    for i in range(len(messageE)):
        print(chr(ord(messageE[i]) + cifraE), end = "")
    Blank()
    sleep(1)
    redo = input("\nDo you want to do another encrypt in Caesar Cipher?(y/N) ")
    if redo == "y" or redo =="Y":
        CipherCaesarEncrypt()
    else:
        Menu()

def CipherCaesarDecrypt():
    Apresentation()
    messageD = input("\nType the text you want to decrypt in Caesar Cipher: ")
    cifraD = int(input("Type the key: "))
    print ("Result: ", end="")
    for i in range(len(messageD)):
        Result = print(chr(ord(messageD[i]) - cifraD), end="")
    Blank()
    sleep(1)
    redo = input("\nDo you want to do another decrypt in Caesar Cipher?(y/N) ")
    if redo == "y" or redo =="Y":
        CipherCaesarDecrypt()
    else:
        Menu()

def ReverseText():
    Apresentation()
    stringReverseText = input("\nType the text you want to reverse: ")
    print("Result: " + stringReverseText[::-1])
    Blank()
    sleep(1)
    redo = input("Do you want to reverse another text?(y/N) ")
    if redo == "y" or redo =="Y":
        ReverseText()
    else:
        Menu()

def HexadecimalEncrypt():
    Apresentation()
    stringHexadecimalE = input("\nType the text you want to transform in hexadecimal: ")
    ResultHexadecimalE = binascii.hexlify(bytes(stringHexadecimalE, "utf-8"))
    ResultHexadecimalE = str(ResultHexadecimalE).strip("b")
    ResultHexadecimalE = ResultHexadecimalE.strip("'")
    ResultHexadecimalE = re.sub(r'(..)', r'\1 ', ResultHexadecimalE).strip()
    print("Result: " + ResultHexadecimalE)
    Blank()
    sleep(1)
    redo = input("Do you want to transform another text in hexadecimal?(y/N) ")
    if redo == "y" or redo =="Y":
        HexadecimalEncrypt()
    else:
        Menu()

def HexadecimalDecrypt():
    Apresentation()
    stringHexadecimalD = input("\nType the sequence of characters you desire to uncover in hexadecimal: ")
    ResultHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8')
    print("Result: " + ResultHexadecimalD)
    Blank()
    sleep(1)
    redo = input("Do you want to uncover another text in hexadecimal?(y/N) ")
    if redo == "y" or redo =="Y":
        HexadecimalDecrypt()
    else:
        Menu()

def Menu():
    Apresentation()
    print("""
    \t [+] Available options:
    \t  1. Encrypt - Md5.
    \t  2. Encrypt - Sha256.
    \t  3. Encrypt - Sha512.
    \t  4. Encrypt - Base64.
    \t  5. Encrypt - Reverse Text.
    \t  6. Encrypt/Decrypt - Cipher Caesar.
    \t  7. Encrypt/Decrypt - Hexadecimal.
    \t  00. Exit.\n""")
    menuChoice = input("   ~~> ")
    if menuChoice == "1":
        Md5Encrypt()
    elif menuChoice == "2":
        Sha256Encrypt()
    elif menuChoice == "3":
        Sha512Encrypt()
    elif menuChoice == "4":
        Base64Encrypt()
    elif menuChoice == "5":
        ReverseText()
    elif menuChoice == "6":
        Apresentation()
        print("""\t [+] Cipher Caesar.
          A) Encrypt.
          B) Decrypt.\n""")
        CDCEncryptOrDecrypt = input("   ~~> ")
        if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
            CipherCaesarEncrypt()
        elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
            CipherCaesarDecrypt()
        else:
            print("Invalid option, try again.")
            sleep(3)
            Apresentation()
            print("""\t [+] Caesar Cipher.
              A) Encrypt.
              B) Decrypt.\n""")
            CDCEncryptOrDecrypt = input("   ~~> ")
            if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
                CipherCaesarEncrypt()
            elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
                CipherCaesarDecrypt()
            else:
                print("You've entered an invalid option twice, going back to menu.")
                sleep(3)
                Menu()
    elif menuChoice == "7":
        Apresentation()
        print("""\t [+] Hexadecimal.
          A) Encrypt.
          B) Decrypt.\n""")
        HexadecimalEncryptOrDecrypt = input("    ~~> ")
        if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
            HexadecimalEncrypt()
        elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
            HexadecimalDecrypt()
        else:
            print("Invalid option, going back to menu.")
            sleep(3)
            Apresentation()
            print("""\t [+] Hexadecimal.
              A) Encrypt.
              B) Decrypt.\n""")
            HexadecimalEncryptOrDecrypt = input("   ~~> ")
            if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
                HexadecimalEncrypt()
            elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
                HexadecimalDecrypt()
            else:
                print("You've entered an invalid option twice, going back to menu.")
                sleep(3)
                Menu()
    elif menuChoice == "00":
        exit(1)
    else:
        print("You've entered an invalid option. Please enter one of the listed options.")
        sleep(3)
        Menu()

Menu()
