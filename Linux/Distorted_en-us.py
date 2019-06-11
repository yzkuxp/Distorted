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

branco = '\033[1;97m'
vermelho = '\033[1;31m'
magneta = '\033[1;35m'
ciano = '\033[1;36m'


if sys.version_info[0] < 3:
    version = python_version()
    print("\033[1;91mYou are using python in version %s which is lower than python3 onward.\033[1;97m" %(version))
    print("\033[1;91mPlease run the tool with a version higher than python 3.x.x.\033[1;97m")
    sleep(3)
    exit(1)

def Clear():
    os.system('clear')

def Blank():
    print("    ")

def Apresentation():
    Clear()
    print ("""\033[1;35m
\t\t   ___________________________________________
\t\t  |                                           |
\t\t  |    ____  _     _           _         _    |
\t\t  |   |    \|_|___| |_ ___ ___| |_ ___ _| |   |
\t\t  |   |  |  | |_ -|  _| . |  _|  _| -_| . |   |
\t\t  |   |____/|_|___|_| |___|_| |_| |___|___|   |
\t\t  |                By: yzkuxp                 |
\t\t  |                                           |
\t\t  |___________________________________________|
    \033[1;97m""")

def Md5Encrypt():
    Apresentation()
    stringMd5 = input("\n\033[1;36mType the text you want to encrypt in Md5\033[1;97m: ")
    ResultMd5 = hashlib.md5(stringMd5.encode())
    print ("\033[1;36mResult\033[1;97m: " + ResultMd5.hexdigest())
    Blank()
    sleep(1)
    redo = input("\033[1;31mDo you want to do another encrypt in Md5?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        Md5Encrypt()
    else:
        Menu()

def Sha256Encrypt():
    Apresentation()
    stringSha256 = input("\n\033[1;36mType the text you want to encrypt in Sha256\033[1;97m: ")
    ResultSha256 = hashlib.sha256(stringSha256.encode())
    print("\033[1;36mResult\033[1;97m: " + ResultSha256.hexdigest())
    Blank()
    sleep(1)
    redo = input("\033[1;31mDo you want to do another encrypt in Sha256?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        Sha256Encrypt()
    else:
        Menu()

def Sha512Encrypt():
    Apresentation()
    stringSha512 = input("\n\033[1;36mType the text you want to encrypt in Sha512\033[1;97m: ")
    ResultSha512 = hashlib.sha512(stringSha512.encode())
    print ("\033[1;36mResult\033[1;97m: " + ResultSha512.hexdigest())
    Blank()
    sleep(1)
    redo = input("\033[1;31mDo you want to do another encrypt in Sha512?(s/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        Sha512Encrypt()
    else:
        Menu()

def Base64Encrypt():
    Apresentation()
    stringBase64E = input("\n\033[1;36mType the text you want to encrypt in Base64\033[1;97m: ")
    ResultBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = ResultBase64E.decode('utf-8')
    print ("\033[1;36mResult\033[1;97m: " + decode)
    Blank()
    sleep(1)
    redo = input("\033[1;31mDo you want to do another encrypt in Base64?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        Base64Encrypt()
    else:
        Menu()

def CipherCaesarEncrypt():
    Apresentation()
    messageE = input("\n\033[1;36mType the text you want to encrypt in Caesar Cipher\033[1;97m: ")
    cifraE = int(input("\033[1;36mType the key\033[1;97m: "))
    print ("\033[1;36mResult\033[1;97m: ", end="")
    for i in range(len(messageE)):
        print(chr(ord(messageE[i]) + cifraE), end = "")
    Blank()
    sleep(1)
    redo = input("\n\033[1;31mDo you want to do another encrypt in Caesar Cipher?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        CipherCaesarEncrypt()
    else:
        Menu()

def CipherCaesarDecrypt():
    Apresentation()
    messageD = input("\n\033[1;36mType the text you want to decrypt in Caesar Cipher\033[1;97m: ")
    cifraD = int(input("\033[1;36mType the key\033[1;97m: "))
    print ("\033[1;36mResult\033[1;97m: ", end="")
    for i in range(len(messageD)):
        Result = print(chr(ord(messageD[i]) - cifraD), end="")
    Blank()
    sleep(1)
    redo = input("\n\033[1;31mDo you want to do another decrypt in Caesar Cipher?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        CipherCaesarDecrypt()
    else:
        Menu()

def ReverseText():
    Apresentation()
    stringReverseText = input("\n\033[1;36mType the text you want to reverse\033[1;97m: ")
    print("\033[1;36mResult\033[1;97m: " + stringReverseText[::-1])
    Blank()
    sleep(1)
    redo = input("\033[1;31mDo you want to reverse another text?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        ReverseText()
    else:
        Menu()

def HexadecimalEncrypt():
    Apresentation()
    stringHexadecimalE = input("\n\033[1;36mType the text you want to transform in hexadecimal\033[1;97m: ")
    ResultHexadecimalE = binascii.hexlify(bytes(stringHexadecimalE, "utf-8"))
    ResultHexadecimalE = str(ResultHexadecimalE).strip("b")
    ResultHexadecimalE = ResultHexadecimalE.strip("'")
    ResultHexadecimalE = re.sub(r'(..)', r'\1 ', ResultHexadecimalE).strip()
    print("\033[1;36mResult\033[1;97m: " + ResultHexadecimalE)
    Blank()
    sleep(1)
    redo = input("\033[1;31mDo you want to transform another text in hexadecimal?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        HexadecimalEncrypt()
    else:
        Menu()

def HexadecimalDecrypt():
    Apresentation()
    stringHexadecimalD = input("\n\033[1;36mType the sequence of characters you desire to uncover in hexadecimal\033[1;97m: ")
    ResultHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8')
    print("\033[1;36mResult\033[1;97m: " + ResultHexadecimalD)
    Blank()
    sleep(1)
    redo = input("\033[1;31mDo you want to uncover another text in hexadecimal?(y/N)\033[1;97m ")
    if redo == "y" or redo =="Y":
        HexadecimalDecrypt()
    else:
        Menu()

def Menu():
    Apresentation()
    print("""
    \t \033[1;36m[+] \033[1;97mAvailable options:
    \t  \033[1;35m1\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mMd5.
    \t  \033[1;35m2\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mSha256.
    \t  \033[1;35m3\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mSha512.
    \t  \033[1;35m4\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mBase64.
    \t  \033[1;35m5\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mReverse Text.
    \t  \033[1;35m6\033[1;97m. \033[1;35mEncrypt/Decrypt \033[1;97m- \033[1;36mCipher Caesar.
    \t  \033[1;35m7\033[1;97m. \033[1;35mEncrypt/Decrypt \033[1;97m- \033[1;36mHexadecimal.
    \t  \033[1;35m00\033[1;97m. Exit.\033[1;97m\n""")
    menuChoice = input("   \033[1;31m~~>\033[1;97m ")
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
        print("""\t \033[1;36m[+] \033[1;97mCipher Caesar.
          \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
          \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
        CDCEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
        if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
            CipherCaesarEncrypt()
        elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
            CipherCaesarDecrypt()
        else:
            print("\033[1;91mInvalid option, try again.\033[1;97m")
            sleep(3)
            Apresentation()
            print("""\t \033[1;36m[+] \033[1;97mCaesar Cipher.
              \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
              \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
            CDCEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
            if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
                CipherCaesarEncrypt()
            elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
                CipherCaesarDecrypt()
            else:
                print("\033[1;91mYou've entered an invalid option twice, going back to menu.\033[1;97m")
                sleep(3)
                Menu()
    elif menuChoice == "7":
        Apresentation()
        print("""\t \033[1;36m[+] \033[1;97mHexadecimal.
          \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
          \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
        HexadecimalEncryptOrDecrypt = input("    \033[1;31m~~>\033[1;97m ")
        if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
            HexadecimalEncrypt()
        elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
            HexadecimalDecrypt()
        else:
            print("\033[1;91mInvalid option, going back to menu.\033[1;97m")
            sleep(3)
            Apresentation()
            print("""\t \033[1;36m[+] \033[1;97mHexadecimal.
              \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
              \033[1;35mB\033[1;97m) \033[1;36mDecrypt\033[1;97m.\n""")
            HexadecimalEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
            if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
                HexadecimalEncrypt()
            elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
                HexadecimalDecrypt()
            else:
                print("\033[1;91mYou've entered an invalid option twice, going back to menu.\033[1;97m")
                sleep(3)
                Menu()
    elif menuChoice == "00":
        exit(1)
    else:
        print("\033[1;91mYou've entered an invalid option. Please enter one of the listed options.\033[1;97m")
        sleep(3)
        Menu()

Menu()
