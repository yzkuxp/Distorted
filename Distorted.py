#!/usr/bin/env python3
#coding: utf-8

# Tool maded in python by myself to encrypt your text.
# Options: Md5, Sha256, Sha512, Base64, Reverse Text, Caesar Cipher, Hexadecimal and Binary.
# By: yzkuxp
# Enjoy ^^


import time;
import hashlib;
from base64 import b64encode, b64decode;
import codecs;
import binascii;
import re;
from time import sleep;
import sys;
import string;
import os;
import platform;

def clear(system):
    if "Win" in system:
        os.system('cls');
    elif "Lin" in system:
        os.system('clear');

system = platform.system();
print(system + " Detected");
time.sleep(3);
clear(system);

set_idk = "";
set_white = "";
set_red = "";
set_magneta = "";
set_cyan = "";

if "Lin" in system:
    set_idk = '\033[1;91m';
    set_white = '\033[1;97m';
    set_red = '\033[1;31m';
    set_magneta = '\033[1;35m';
    set_cyan = '\033[1;36m';
if "Win" in system:
    set_idk = "";
    set_white = "";
    set_red = "";
    set_magneta = "";
    set_cyan = "";

def Main():
    def Clear():
        os.system('clear');

    def Blank():
        print("    ");

    def Apresentation():
        Clear();
        print (set_magneta + """
  \t    ▓█████▄  ██▓  ██████ ▄▄▄█████▓ ▒█████   ██▀███  ▄▄▄█████▓▓█████ ▓█████▄
  \t    ▒██▀ ██▌▓██▒▒██    ▒ ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒▓█   ▀ ▒██▀ ██▌
  \t    ░██   █▌▒██▒░ ▓██▄   ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░▒███   ░██   █▌
  \t    ░▓█▄   ▌░██░  ▒   ██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ ▒▓█  ▄ ░▓█▄   ▌
  \t    ░▒████▓ ░██░▒██████▒▒  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ ░▒████▒░▒████▓
  \t    ▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   ░░ ▒░ ░ ▒▒▓  ▒
  \t    ░ ▒  ▒  ▒ ░░ ░▒  ░ ░    ░      ░ ▒ ▒░   ░▒ ░ ▒░    ░     ░ ░  ░ ░ ▒  ▒
  \t    ░ ░  ░  ▒ ░░  ░  ░    ░      ░ ░ ░ ▒    ░░   ░   ░         ░    ░ ░  ░
  \t    ░     ░        ░               ░ ░     ░                 ░  ░   ░
  \t    ░                                                               ░
        """ + set_white);

    # Md5 --------------------------------------------------------------------------
    def Md5Encrypt():
        try:
            Apresentation();
            stringMd5 = input(set_cyan + "\nType the text you want to encrypt in Md5: " + set_white);
            ResultMd5 = hashlib.md5(stringMd5.encode());
            print (set_cyan+ "Result: " + set_white + ResultMd5.hexdigest());
            Blank();
            sleep(1);
            redo = input(set_red + "Do you want to do another encrypt in Md5?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                Md5Encrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Sha256 -----------------------------------------------------------------------
    def Sha256Encrypt():
        try:
            Apresentation();
            stringSha256 = input(set_cyan + "\nType the text you want to encrypt in Sha256: " + set_white);
            ResultSha256 = hashlib.sha256(stringSha256.encode());
            print(set_cyan + "Result: " + set_white + ResultSha256.hexdigest());
            Blank();
            sleep(1);
            redo = input(set_red + "Do you want to do another encrypt in Sha256?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                Sha256Encrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Sha512 -----------------------------------------------------------------------
    def Sha512Encrypt():
        try:
            Apresentation();
            stringSha512 = input(set_cyan + "\nType the text you want to encrypt in Sha512: " + set_white);
            ResultSha512 = hashlib.sha512(stringSha512.encode());
            print (set_cyan + "Result: " + set_white + ResultSha512.hexdigest());
            Blank();
            sleep(1);
            redo = input(set_red + "Do you want to do another encrypt in Sha512?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                Sha512Encrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Base64 -----------------------------------------------------------------------
    def Base64Encrypt():
        try:
            Apresentation();
            stringBase64E = input(set_cyan + "\nType the text you want to encrypt in Base64: " + set_white);
            ResultBase64E = b64encode(stringBase64E.encode('utf-8'));
            decode = ResultBase64E.decode('utf-8');
            print (set_cyan + "Result: " + set_white + decode);
            Blank();
            sleep(1);
            redo = input(set_red + "Do you want to do another encrypt in Base64?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                Base64Encrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    def Base64Decrypt():
        try:
            Apresentation();
            stringBase64D = str(input(set_cyan + "Type the text you want to decrypt in Base64: " + set_white));
            try:
                decrypt = b64decode(stringBase64D).decode('utf-8');
                print(set_cyan + "Result: " + set_white + decrypt);
                Blank();
            except:
                print(set_cyan + "Error in padding." + set_white);
                sleep(3);
                Base64Decrypt();
            redo = input(set_red + "Do you want to do another decrypt in Base64?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                Base64Decrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Binary -----------------------------------------------------------------------
    def BinaryEncrypt(encoding='utf-8', errors='surrogatepass'):
        try:
            Apresentation();
            try:
                binaryE = input(set_cyan + "\nType the text you want to encrypt in Binary: " + set_white);
                bits = bin(int(binascii.hexlify(binaryE.encode(encoding, errors)), 16))[2:];
                result = bits.zfill(8 * ((len(bits) + 7) // 8));
                print(set_cyan + "Result: " + set_white + result);
            except:
                print(set_cyan+ "Value Error!"+ set_white);
                sleep(3);
                BinaryEncrypt();
            redo = input(set_red + "\nDo you want to do another encrypt in Binary?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                BinaryEncrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    def intToBytes(i):
        try:
            hex_string = '%x' % i;
            n = len(hex_string);
            return binascii.unhexlify(hex_string.zfill(n + (n & 1)));
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    def BinaryDecrypt(encoding='utf-8', errors='surrogatepass'):
        try:
            Apresentation();
            try:
                binaryD = input(set_cyan + "Type the binary code you desire to decrypt: " + set_white);
                binaryD = binaryD.replace(" ", "");
                n = int(binaryD, 2);
                print(set_cyan + "Result: " + set_white + intToBytes(n).decode(encoding, errors));
            except:
                print(set_cyan + "Value Error!" + set_white);
                sleep(3);
                BinaryDecrypt();
            redo = input(set_red + "\nDo you want to do another decrypt in Binary?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                BinaryDecrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Caesar Cipher ----------------------------------------------------------------
    def CaesarCipherEncrypt():
        try:
            Apresentation();
            messageE = input(set_cyan + "\nType the text you want to encrypt in Caesar Cipher: " + set_white);
            cifraE = int(input(set_cyan + "Type the key: " + set_white));
            print(set_cyan + "Result: " + set_white, end = "");
            for i in range(len(messageE)):
                print(chr(ord(messageE[i]) + cifraE), end = "");
            Blank();
            sleep(1);
            redo = input(set_red + "\nDo you want to do another encrypt in Caesar Cipher?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                CaesarCipherEncrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    def CaesarCipherDecrypt():
        try:
            Apresentation();
            messageD = input(set_cyan + "\nType the text you want to decrypt in Caesar Cipher: " + set_white);
            cifraD = int(input(set_cyan + "Type the key: " + set_white));
            print (set_cyan + "Result: " + set_white, end="");
            for i in range(len(messageD)):
                Result = print(chr(ord(messageD[i]) - cifraD), end = "");
            Blank();
            sleep(1);
            redo = input(set_red + "\nDo you want to do another decrypt in Caesar Cipher?(y/N) " + set_white);
            if redo == "y" or redo == "Y":
                CaesarCipherDecrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Reverse Text -----------------------------------------------------------------
    def ReverseText():
        try:
            Apresentation();
            stringReverseText = input(set_cyan + "\nType the text you want to reverse: " + set_white);
            print(set_cyan + "Result: " + set_white + stringReverseText[::-1]);
            Blank();
            sleep(1);
            redo = input(set_red + "Do you want to reverse another text?(y/N) " + set_white);
            if redo == "y" or redo == "Y":
                ReverseText();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Hexadecimal ------------------------------------------------------------------
    def HexadecimalEncrypt():
        try:
            Apresentation();
            stringHexadecimalE = input(set_cyan + "\nType the text you want to transform in hexadecimal: " + set_white);
            ResultHexadecimalE = binascii.hexlify(bytes(stringHexadecimalE, "utf-8"));
            ResultHexadecimalE = str(ResultHexadecimalE).strip("b");
            ResultHexadecimalE = ResultHexadecimalE.strip("'");
            ResultHexadecimalE = re.sub(r'(..)', r'\1 ', ResultHexadecimalE).strip();
            print(set_cyan + "Result: " + set_white + ResultHexadecimalE);
            Blank();
            sleep(1);
            redo = input(set_red + "Do you want to transform another text in hexadecimal?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                HexadecimalEncrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    def HexadecimalDecrypt():
        try:
            Apresentation();
            stringHexadecimalD = input(set_cyan + "\nType the sequence of characters you desire to uncover in hexadecimal: " + set_white);
            ResultHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8');
            print(set_cyan + "Result: " + set_white + ResultHexadecimalD);
            Blank();
            sleep(1);
            redo = input(set_red + "Do you want to uncover another text in hexadecimal?(y/N) " + set_white);
            if redo == "y" or redo =="Y":
                HexadecimalDecrypt();
            else:
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    # Menu -------------------------------------------------------------------------
    def Menu():
        try:
            Apresentation();
            print(set_cyan+ "\t [+] " + set_white + "Available options:");
            print("\t  " + set_magneta + "1" + set_white + ". " + set_magneta + "Encrypt " + set_white+ "- " + set_cyan + "Md5.");
            print("\t  " + set_magneta + "2" + set_white + ". " + set_magneta + "Encrypt " + set_white+ "- " + set_cyan + "Sha256.");
            print("\t  " + set_magneta + "3" + set_white + ". " + set_magneta + "Encrypt " + set_white+ "- " + set_cyan + "Sha512.");
            print("\t  " + set_magneta + "4" + set_white + ". " + set_magneta + "Encrypt/Decrypt " + set_white+ "- " + set_cyan + "Base64.");
            print("\t  " + set_magneta + "5" + set_white + ". " + set_magneta + "Encrypt " + set_white+ "- " + set_cyan + "Reverse Text.");
            print("\t  " + set_magneta + "6" + set_white + ". " + set_magneta + "Encrypt/Decrypt " + set_white+ "- " + set_cyan + "Caesar Cipher.");
            print("\t  " + set_magneta + "7" + set_white + ". " + set_magneta + "Encrypt/Decrypt " + set_white+ "- " + set_cyan + "Hexadecimal.");
            print("\t  " + set_magneta + "8" + set_white + ". " + set_magneta + "Encrypt/Decrypt " + set_white+ "- " + set_cyan + "Binary.");
            print("\t  " + set_magneta + "q" + set_white + ". " + set_cyan + "Exit.");
            menuChoice = input(set_red + "   ~~> " + set_white);
            if menuChoice == "1":
                Md5Encrypt();
            elif menuChoice == "2":
                Sha256Encrypt();

            elif menuChoice == "3":
                Sha512Encrypt();

            elif menuChoice == "4":
                def Base64Opt():
                    Apresentation();
                    print("\t " + set_cyan + "[+] " + set_white + "Base64.");
                    print("\t  " + set_magneta + "A" + set_white + ") " + set_cyan + "Encrypt." + set_white);
                    print("\t  " + set_magneta + "B" + set_white + ") " + set_cyan + "Decrypt." + set_white);
                    print("\t  " + set_magneta + "q" + set_white + ") " + set_cyan + "Go to the menu." + set_white + "\n");
                    Base64EncryptOrDecrypt = input("   " + set_red + "~~> " + set_white);
                    if (Base64EncryptOrDecrypt == "A") or (Base64EncryptOrDecrypt == "a"):
                        Base64Encrypt();
                    elif (Base64EncryptOrDecrypt == "B" or Base64EncryptOrDecrypt == "b"):
                        Base64Decrypt();
                    elif (Base64EncryptOrDecrypt == "Q" or Base64EncryptOrDecrypt == "q"):
                        Menu();
                    else:
                        print(set_orange + "You've entered an invalid option. Please enter one of the listed options." + set_white);
                        sleep(3);
                        Base64Opt();
                Base64Opt();

            elif menuChoice == "5":
                ReverseText();

            elif menuChoice == "6":
                def CaesarCipherOpt():
                    Apresentation();
                    print("\t " + set_cyan + "[+] " + set_white + "Caesar Cipher.");
                    print("\t  " + set_magneta + "A" + set_white + ") " + set_cyan + "Encrypt." + set_white);
                    print("\t  " + set_magneta + "B" + set_white + ") " + set_cyan + "Decrypt." + set_white);
                    print("\t  " + set_magneta + "q" + set_white + ") " + set_cyan + "Go to the menu." + set_white + "\n");
                    CDCEncryptOrDecrypt = input("   " + set_red + "~~> " + set_white);
                    if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
                        CaesarCipherEncrypt();
                    elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
                        CaesarCipherDecrypt();
                    elif (CDCEncryptOrDecrypt == "Q") or (CDCEncryptOrDecrypt == "q"):
                        Menu();
                    else:
                        print(set_orange + "You've entered an invalid option. Please enter one of the listed options." + set_white);
                        sleep(3);
                        CaesarCipherOpt();
                CaesarCipherOpt();

            elif menuChoice == "7":
                def HexadecimalOpt():
                    Apresentation();
                    print("\t " + set_cyan + "[+] " + set_white + "Hexadecimal.");
                    print("\t  " + set_magneta + "A" + set_white + ") " + set_cyan + "Encrypt." + set_white);
                    print("\t  " + set_magneta + "B" + set_white + ") " + set_cyan + "Decrypt." + set_white);
                    print("\t  " + set_magneta + "q" + set_white + ") " + set_cyan + "Go to the menu." + set_white + "\n");
                    HexadecimalEncryptOrDecrypt = input("   " + set_red + "~~> " + set_white);
                    if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
                        HexadecimalEncrypt();
                    elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
                        HexadecimalDecrypt();
                    elif (HexadecimalEncryptOrDecrypt == "Q") or (HexadecimalEncryptOrDecrypt == "q"):
                        Menu();
                    else:
                        print(set_orange + "You've entered an invalid option. Please enter one of the listed options." + set_white);
                        sleep(3);
                        HexadecimalOpt();
                HexadecimalOpt();

            elif menuChoice == "8":
                def BinaryOpt():
                    Apresentation();
                    print("\t " + set_cyan + "[+] " + set_white + "Binary.");
                    print("\t  " + set_magneta + "A" + set_white + ") " + set_cyan + "Encrypt." + set_white);
                    print("\t  " + set_magneta + "B" + set_white + ") " + set_cyan + "Decrypt." + set_white);
                    print("\t  " + set_magneta + "q" + set_white + ") " + set_cyan + "Go to the menu." + set_white + "\n");
                    BinaryEncryptOrDecrypt = input("   " + set_red + "~~> " + set_white);
                    if (BinaryEncryptOrDecrypt == "A") or (BinaryEncryptOrDecrypt == "a"):
                        BinaryEncrypt();
                    elif (BinaryEncryptOrDecrypt == "B") or (BinaryEncryptOrDecrypt == "b"):
                        BinaryDecrypt();
                    elif (BinaryEncryptOrDecrypt == "Q") or (BinaryEncryptOrDecrypt == "q"):
                        Menu();
                    else:
                        print(set_orange + "You've entered an invalid option. Please enter one of the listed options." + set_white);
                        sleep(3);
                        BinaryOpt();
                BinaryOpt();

            elif (menuChoice == "q") or (menuChoice == "Q"):
                exit(1);

            else:
                print(set_orange + "You've entered an invalid option. Please enter one of the listed options." + set_white);
                sleep(3);
                Menu();
        except KeyboardInterrupt:
            print ("\n");
            print (set_magneta + "You have pressed Ctrl+C.\n");
            sys.exit();

    Menu();

Main();
