# Tool maded in python by myself to encrypt your text.
# Options: Md5, Sha256, Sha512, Base64, Reverse Text, Caesar Cipher and Hexadecimal.
# By: yzkuxp
# Enjoy ^^

#!/usr/bin/env python3
#coding: utf-8

import time
import hashlib
from base64 import b64encode, b64decode
import codecs
import binascii
import re
from time import sleep
import sys
import string
import os
import platform

def clear(system):
    if "Win" in system:
        os.system('cls')
    elif "Lin" in system:
        os.system('clear')

system = platform.system()
print(system + " Detected")
time.sleep(3)
clear(system)

def Linux():
    set_white = '\033[1;97m'
    set_red = '\033[1;31m'
    set_magneta = '\033[1;35m'
    set_cyan = '\033[1;36m'

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

    # Md5 --------------------------------------------------------------------------
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

    # Sha256 -----------------------------------------------------------------------
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

    # Sha512 -----------------------------------------------------------------------
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

    # Base64 -----------------------------------------------------------------------
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

    def Base64Decrypt():
        Apresentation()
        stringBase64D = str(input("\033[1;36mType the text you want to decrypt in Base64\033[1;97m: "))
        Blank()
        try:
            decrypt = b64decode(stringBase64D).decode('utf-8')
            print(decrypt)
            Blank()
        except:
            print("\033[1;36mError in padding.\033[1;97m")
            sleep(3)
            Base64Decrypt()
        redo = input("\033[1;31mDo you want to do another decrypt in Base64?(y/N)\033[1;97m ")
        if redo == "y" or redo =="Y":
            Base64Decrypt()
        else:
            Menu()

    # Binary -----------------------------------------------------------------------
    def BinaryEncrypt(encoding='utf-8', errors='surrogatepass'):
        Apresentation()
        try:
            binaryE = input("\n\033[1;36mType the text you want to encrypt in Binary\033[1;97m: ")
            Blank()
            bits = bin(int(binascii.hexlify(binaryE.encode(encoding, errors)), 16))[2:]
            print(bits.zfill(8 * ((len(bits) + 7) // 8)))
            Blank()
        except:
            print("\033[1;36mValue Error!\033[1;97m")
            sleep(3)
            BinaryEncrypt()
        redo = input("\n\033[1;31mDo you want to do another encrypt in Binary?(y/N)\033[1;97m ")
        if redo == "y" or redo =="Y":
            BinaryEncrypt()
        else:
            Menu()

    def intToBytes(i):
        hex_string = '%x' % i
        n = len(hex_string)
        return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

    def BinaryDecrypt(encoding='utf-8', errors='surrogatepass'):
        Apresentation()
        try:
            binaryD = input("\033[1;36mType the binary code you desire to decrypt\033[1;97m: ")
            binaryD = binaryD.replace(" ", "")
            n = int(binaryD, 2)
            Blank()
            print(intToBytes(n).decode(encoding, errors))
            Blank()
        except:
            print("\033[1;36mValue Error!\033[1;97m")
            sleep(3)
            BinaryDecrypt()
        redo = input("\n\033[1;31mDo you want to do another decrypt in Binary?(y/N)\033[1;97m ")
        if redo == "y" or redo =="Y":
            BinaryDecrypt()
        else:
            Menu()

    # Cipher Caesar ----------------------------------------------------------------
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
            Result = print(chr(ord(messageD[i]) - cifraD), end = "")
        Blank()
        sleep(1)
        redo = input("\n\033[1;31mDo you want to do another decrypt in Caesar Cipher?(y/N)\033[1;97m ")
        if redo == "y" or redo == "Y":
            CipherCaesarDecrypt()
        else:
            Menu()

    # Reverse Text -----------------------------------------------------------------
    def ReverseText():
        Apresentation()
        stringReverseText = input("\n\033[1;36mType the text you want to reverse\033[1;97m: ")
        print("\033[1;36mResult\033[1;97m: " + stringReverseText[::-1])
        Blank()
        sleep(1)
        redo = input("\033[1;31mDo you want to reverse another text?(y/N)\033[1;97m ")
        if redo == "y" or redo == "Y":
            ReverseText()
        else:
            Menu()

    # Hexadecimal ------------------------------------------------------------------
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

    # Menu -------------------------------------------------------------------------
    def Menu():
        Apresentation()
        print("""
        \t \033[1;36m[+] \033[1;97mAvailable options:
        \t  \033[1;35m1\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mMd5.
        \t  \033[1;35m2\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mSha256.
        \t  \033[1;35m3\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mSha512.
        \t  \033[1;35m4\033[1;97m. \033[1;35mEncrypt/Decrypt \033[1;97m- \033[1;36mBase64.
        \t  \033[1;35m5\033[1;97m. \033[1;35mEncrypt\033[1;97m - \033[1;36mReverse Text.
        \t  \033[1;35m6\033[1;97m. \033[1;35mEncrypt/Decrypt \033[1;97m- \033[1;36mCipher Caesar.
        \t  \033[1;35m7\033[1;97m. \033[1;35mEncrypt/Decrypt \033[1;97m- \033[1;36mHexadecimal.
        \t  \033[1;35m8\033[1;97m. \033[1;35mEncrypt/Decrypt \033[1;97m- \033[1;36mBinary.
        \t  \033[1;35mq\033[1;97m. Exit.\033[1;97m\n""")
        menuChoice = input("   \033[1;31m~~>\033[1;97m ")
        if menuChoice == "1":
            Md5Encrypt()
        elif menuChoice == "2":
            Sha256Encrypt()
        elif menuChoice == "3":
            Sha512Encrypt()
        elif menuChoice == "4":
            Apresentation()
            print("""\t \033[1;36m[+] \033[1;97mBase64.
              \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
              \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
            Base64EncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
            if (Base64EncryptOrDecrypt == "A") or (Base64EncryptOrDecrypt == "a"):
                Base64Encrypt()
            elif (Base64EncryptOrDecrypt == "B" or Base64EncryptOrDecrypt == "b"):
                Base64Decrypt()
            else:
                print("\033[1;91mInvalid option, try again.\033[1;97m")
                sleep(3)
                Apresentation()
                print("""\t \033[1;36m[+] \033[1;97mBase64.
                  \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
                  \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
                Base64EncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
                if (Base64EncryptOrDecrypt == "A") or (Base64EncryptOrDecrypt == "a"):
                    Base64Encrypt()
                elif (Base64EncryptOrDecrypt == "B") or (Base64EncryptOrDecrypt == "b"):
                    Base64Decrypt()
                else:
                    print("\033[1;91mYou've entered an invalid option twice, going back to menu.\033[1;97m")
                    sleep(3)
                    Menu()
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
                  \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
                HexadecimalEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
                if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
                    HexadecimalEncrypt()
                elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
                    HexadecimalDecrypt()
                else:
                    print("\033[1;91mYou've entered an invalid option twice, going back to menu.\033[1;97m")
                    sleep(3)
                    Menu()
        elif menuChoice == "8":
            Apresentation()
            print("""\t \033[1;36m[+] \033[1;97mBinary.
              \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
              \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
            BinaryEncryptOrDecrypt = input("    \033[1;31m~~>\033[1;97m ")
            if (BinaryEncryptOrDecrypt == "A") or (BinaryEncryptOrDecrypt == "a"):
                BinaryEncrypt()
            elif (BinaryEncryptOrDecrypt == "B") or (BinaryEncryptOrDecrypt == "b"):
                BinaryDecrypt()
            else:
                print("\033[1;91mInvalid option, going back to menu.\033[1;97m")
                sleep(3)
                Apresentation()
                print("""\t \033[1;36m[+] \033[1;97mBinary.
                  \033[1;35mA\033[1;97m) \033[1;36mEncrypt.\033[1;97m
                  \033[1;35mB\033[1;97m) \033[1;36mDecrypt.\033[1;97m\n""")
                BinaryEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
                if (BinaryEncryptOrDecrypt == "A") or (BinaryEncryptOrDecrypt == "a"):
                    BinaryEncrypt()
                elif (BinaryEncryptOrDecrypt == "B") or (BinaryEncryptOrDecrypt == "b"):
                    BinaryDecrypt()
                else:
                    print("\033[1;91mYou've entered an invalid option twice, going back to menu.\033[1;97m")
                    sleep(3)
                    Menu()
        elif (menuChoice == "q") or (menuChoice == "Q"):
            exit(1)
        else:
            print("\033[1;91mYou've entered an invalid option. Please enter one of the listed options.\033[1;97m")
            sleep(3)
            Menu()

    Menu()
# End for Linux.

def Windows():
    if sys.version_info[0] < 3:
        version = python_version()
        print("You are using python in version %s which is lower than python3 onward." %(version))
        print("Please run the tool with a version higher than python 3.x.x.")
        sleep(3)
        exit(1)

    def Clear():
        os.system('clear')

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

    # Md5 --------------------------------------------------------------------------
    def Md5Encrypt():
        Apresentation()
        stringMd5 = input("Type the text you want to encrypt in Md5: ")
        ResultMd5 = hashlib.md5(stringMd5.encode())
        print ("Result: " + ResultMd5.hexdigest())
        Blank()
        sleep(1)
        redo = input("Do you want to do another encrypt in Md5?(y/N) ")
        if redo == "y" or redo =="Y":
            Md5Encrypt()
        else:
            Menu()

    # Sha256 -----------------------------------------------------------------------
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

    # Sha512 -----------------------------------------------------------------------
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

    # Base64 -----------------------------------------------------------------------
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

    def Base64Decrypt():
        Apresentation()
        stringBase64D = str(input("Type the text you want to decrypt in Base64: "))
        Blank()
        try:
            decrypt = b64decode(stringBase64D).decode('utf-8')
            print(decrypt)
            Blank()
        except:
            print("Error in padding.")
            sleep(3)
            Base64Decrypt()
        redo = input("Do you want to do another decrypt in Base64?(y/N) ")
        if redo == "y" or redo =="Y":
            Base64Decrypt()
        else:
            Menu()

    # Binary -----------------------------------------------------------------------
    def BinaryEncrypt(encoding='utf-8', errors='surrogatepass'):
        Apresentation()
        try:
            binaryE = input("\nType the text you want to encrypt in Binary: ")
            Blank()
            bits = bin(int(binascii.hexlify(binaryE.encode(encoding, errors)), 16))[2:]
            print(bits.zfill(8 * ((len(bits) + 7) // 8)))
            Blank()
        except:
            print("Value Error!")
            sleep(3)
            BinaryEncrypt()
        redo = input("\nDo you want to do another encrypt in Binary?(y/N) ")
        if redo == "y" or redo =="Y":
            BinaryEncrypt()
        else:
            Menu()

    def intToBytes(i):
        hex_string = '%x' % i
        n = len(hex_string)
        return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

    def BinaryDecrypt(encoding='utf-8', errors='surrogatepass'):
        Apresentation()
        try:
            binaryD = input("Type the binary code you desire to decrypt: ")
            binaryD = binaryD.replace(" ", "")
            n = int(binaryD, 2)
            Blank()
            print(intToBytes(n).decode(encoding, errors))
            Blank()
        except:
            print("Value Error!")
            sleep(3)
            BinaryDecrypt()
        redo = input("\nDo you want to do another decrypt in Binary?(y/N) ")
        if redo == "y" or redo =="Y":
            BinaryDecrypt()
        else:
            Menu()

    # Cipher Caesar ----------------------------------------------------------------
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
            Result = print(chr(ord(messageD[i]) - cifraD), end = "")
        Blank()
        sleep(1)
        redo = input("\nDo you want to do another decrypt in Caesar Cipher?(y/N) ")
        if redo == "y" or redo == "Y":
            CipherCaesarDecrypt()
        else:
            Menu()

    # Reverse Text -----------------------------------------------------------------
    def ReverseText():
        Apresentation()
        stringReverseText = input("\nType the text you want to reverse: ")
        print("Result: " + stringReverseText[::-1])
        Blank()
        sleep(1)
        redo = input("Do you want to reverse another text?(y/N) ")
        if redo == "y" or redo == "Y":
            ReverseText()
        else:
            Menu()

    # Hexadecimal ------------------------------------------------------------------
    def HexadecimalEncrypt():
        Apresentation()
        stringHexadecimalE = input("Type the text you want to transform in hexadecimal: ")
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

    # Menu -------------------------------------------------------------------------
    def Menu():
        Apresentation()
        print("""
        \t [+] Available options:
        \t  1. Encrypt - Md5.
        \t  2. Encrypt - Sha256.
        \t  3. Encrypt - Sha512.
        \t  4. Encrypt/Decrypt - Base64.
        \t  5. Encrypt - Reverse Text.
        \t  6. Encrypt/Decrypt - Cipher Caesar.
        \t  7. Encrypt/Decrypt - Hexadecimal.
        \t  8. Encrypt/Decrypt - Binary.
        \t  q. Exit.\n""")
        menuChoice = input("   ~~> ")
        if menuChoice == "1":
            Md5Encrypt()
        elif menuChoice == "2":
            Sha256Encrypt()
        elif menuChoice == "3":
            Sha512Encrypt()
        elif menuChoice == "4":
            Apresentation()
            print("""\t [+] Base64.
              A) Encrypt.
              B) Decrypt.\n""")
            Base64EncryptOrDecrypt = input("   ~~> ")
            if (Base64EncryptOrDecrypt == "A") or (Base64EncryptOrDecrypt == "a"):
                Base64Encrypt()
            elif (Base64EncryptOrDecrypt == "B" or Base64EncryptOrDecrypt == "b"):
                Base64Decrypt()
            else:
                print("Invalid option, try again.")
                sleep(3)
                Apresentation()
                print("""\t [+] Base64.
                  A) Encrypt.
                  B) Decrypt.\n""")
                Base64EncryptOrDecrypt = input("   ~~> ")
                if (Base64EncryptOrDecrypt == "A") or (Base64EncryptOrDecrypt == "a"):
                    Base64Encrypt()
                elif (Base64EncryptOrDecrypt == "B") or (Base64EncryptOrDecrypt == "b"):
                    Base64Decrypt()
                else:
                    print("You've entered an invalid option twice, going back to menu.")
                    sleep(3)
                    Menu()
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
        elif menuChoice == "8":
            Apresentation()
            print("""\t [+] Binary.
              A) Encrypt.
              B) Decrypt.\n""")
            BinaryEncryptOrDecrypt = input("    ~~> ")
            if (BinaryEncryptOrDecrypt == "A") or (BinaryEncryptOrDecrypt == "a"):
                BinaryEncrypt()
            elif (BinaryEncryptOrDecrypt == "B") or (BinaryEncryptOrDecrypt == "b"):
                BinaryDecrypt()
            else:
                print("Invalid option, going back to menu.")
                sleep(3)
                Apresentation()
                print("""\t [+] Binary.
                  A) Encrypt.
                  B) Decrypt.""")
                BinaryEncryptOrDecrypt = input("   ~~> ")
                if (BinaryEncryptOrDecrypt == "A") or (BinaryEncryptOrDecrypt == "a"):
                    BinaryEncrypt()
                elif (BinaryEncryptOrDecrypt == "B") or (BinaryEncryptOrDecrypt == "b"):
                    BinaryDecrypt()
                else:
                    print("You've entered an invalid option twice, going back to menu.")
                    sleep(3)
                    Menu()
        elif (menuChoice == "q") or (menuChoice == "Q"):
            exit(1)
        else:
            print("You've entered an invalid option. Please enter one of the listed options.")
            sleep(3)
            Menu()

    Menu()
# End for Windows.

if "Win" in system:
    Windows()
elif "Lin" in system:
    Linux()
