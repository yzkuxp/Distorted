# Tool maded by myself in python for encrypt your text.
# Encrypt options: Md5, Sha256, Sha512, Base64, Reverte Text, Cesar Cipher and Hexadecimal.
# OBS: The tool it's still in development. And may have some bugs, or some pendent features.
# Developed by: yzkuxp
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
    print("\033[1;91mVocê está usando o python na versão %s ela é inferior ao python3 em diante.\033[1;97m" %(version))
    print("\033[1;91mPor favor execute a ferramenta utilizando python3 em diante\033[1;97m")
    sleep(3)
    exit(1)

sistemaOperacional = input("\nOlá, qual sistema operacional você está utlizando?\n  A) Linux.\n  B) Windows.\n\n ~~> ")
def clearAgain():
    print ("Opção inválida. Insira uma opção válida.")
    sleep(2)
    sistemaOperacional = sistemaOperacional = input("\n\nOlá, qual sistema operacional você está utlizando?\n  A) Linux.\n  B) Windows.\n\n ~~> ")
    if (sistemaOperacional == "A") or (sistemaOperacional == "a"):
        linuxClear = os.system('clear')
    elif (sistemaOperacional == "B") or (sistemaOperacional == "b"):
        windowsClear = os.system('cls')
    else:
        clearAgain()
def clear():
    if (sistemaOperacional == "A") or (sistemaOperacional == "a"):
        linuxClear = os.system('clear')
    elif (sistemaOperacional == "B") or (sistemaOperacional == "b"):
        windowsClear = os.system('cls')
    else:
        clearAgain()

def Vazio():
    print("    ")

def Apresentacao():
    clear()
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
    Apresentacao()
    stringMd5 = input("\n\033[1;36mDigite o texto que deseja criptografar em Md5\033[1;97m: ")
    resultadoMd5 = hashlib.md5(stringMd5.encode())
    print ("\033[1;36mResultado\033[1;97m: " + resultadoMd5.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Md5?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Md5Encrypt()
    else:
        Menu()

def Sha256Encrypt():
    Apresentacao()
    stringSha256 = input("\n\033[1;36mDigite o texto que deseja criptografar em Sha256\033[1;97m: ")
    resultadoSha256 = hashlib.sha256(stringSha256.encode())
    print("\033[1;36mResultado\033[1;97m: " + resultadoSha256.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Sha256?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Sha256Encrypt()
    else:
        Menu()

def Sha512Encrypt():
    Apresentacao()
    stringSha512 = input("\n\033[1;36mDigite o texto que deseja criptografar em Sha512\033[1;97m: ")
    resultadoSha512 = hashlib.sha512(stringSha512.encode())
    print ("\033[1;36mResultado\033[1;97m: " + resultadoSha512.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Sha512?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Sha512Encrypt()
    else:
        Menu()

def Base64Encrypt():
    Apresentacao()
    stringBase64E = input("\n\033[1;36mDigite o texto que deseja criptografar em Base64\033[1;97m: ")
    resultadoBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = resultadoBase64E.decode('utf-8')
    print ("\033[1;36mResultado\033[1;97m: " + decode)
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Base64?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Base64Encrypt()
    else:
        Menu()

def CifraDeCesarEncrypt():
    Apresentacao()
    mensagemE = input("\n\033[1;36mDigite a frase que deseja criptografar\033[1;97m: ")
    cifraE = int(input("Digite a chave: "))
    print ("\033[1;36mResultado\033[1;97m: ", end="")
    for i in range(len(mensagemE)):
        print(chr(ord(mensagemE[i]) + cifraE), end = "")
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Cifra de Cesar?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        CifraDeCesarEncrypt()
    else:
        Menu()

def CifraDeCesarDecrypt():
    Apresentacao()
    mensagemD = input("\n\033[1;36mDigite a frase que deseja descriptografar\033[1;97m: ")
    cifraD = int(input("Digite a chave: "))
    print ("\033[1;36mResultado\033[1;97m: ", end="")
    for i in range(len(mensagemD)):
        resultado = print(chr(ord(mensagemD[i]) - cifraD), end="")
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja descriptografar outra frase em Cifra de Cesar?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        CifraDeCesarDecrypt()
    else:
        Menu()

def InverterTexto():
    Apresentacao()
    stringInverterTexto = input("\n\033[1;36mDigite o texto que deseja inverter\033[1;36m: ")
    print("\033[1;36mResultado\033[1;97m: " + stringInverterTexto[::-1])
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja inverter outro texto?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        InverterTexto()
    else:
        Menu()

def HexadecimalEncrypt():
    Apresentacao()
    stringHexadecimalE = input("\n\033[1;36mDigite o texto que deseja passar para hexadecimal\033[1;97m: ")
    ResultadoHexadecimalE = binascii.hexlify(bytes(stringHexadecimalE, "utf-8"))
    ResultadoHexadecimalE = str(ResultadoHexadecimalE).strip("b")
    ResultadoHexadecimalE = ResultadoHexadecimalE.strip("'")
    ResultadoHexadecimalE = re.sub(r'(..)', r'\1 ', ResultadoHexadecimalE).strip()
    print("\033[1;36mResultado\033[1;97m: " + ResultadoHexadecimalE)
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja passar outro texto para hexadecimal?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        HexadecimalEncrypt()
    else:
        Menu()

def HexadecimalDecrypt():
    Apresentacao()
    stringHexadecimalD = input("\n\033[1;36mDigite o texto em hexadecimal que deseja desvendar\033[1;97m: ")
    ResultadoHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8')
    print("\033[1;36mResultado\033[1;97m: " + ResultadoHexadecimalD)
    Vazio()
    refazer = input("\033[1;31mDeseja desvendar outro texto em hexadecimal(s/N)\033[1;97m ")
    sleep(1)
    if refazer == "s" or refazer =="S":
        HexadecimalDecrypt()
    else:
        Menu()

def Menu():
    Apresentacao()
    print("\n\t \033[1;36m[+] \033[1;97mOpções disponíveis:\n\t  \033[1;35m1\033[1;97m. \033[1;36mMd5.\n\t  \033[1;35m2\033[1;97m. \033[1;36mSha256.\n\t  \033[1;35m3\033[1;97m. \033[1;36mSha512.\n\t  \033[1;35m4\033[1;97m. \033[1;36mBase64.\n\t  \033[1;35m5\033[1;97m. \033[1;36mInverter Texto.\n\t  \033[1;35m6\033[1;97m. \033[1;35mENCRYPT/DECRYPT \033[1;97m- \033[1;36mCifra de César.\n\t  \033[1;35m7\033[1;97m. \033[1;35mENCRYPT/DECRYPT \033[1;97m- \033[1;36mHexadecimal.\n\t  \033[1;35m00\033[1;97m. Exit.\033[1;97m\n")
    escolhaMenu = input("   \033[1;31m~~>\033[1;97m ")
    if escolhaMenu == "1":
        Md5Encrypt()
    elif escolhaMenu == "2":
        Sha256Encrypt()
    elif escolhaMenu == "3":
        Sha512Encrypt()
    elif escolhaMenu == "4":
        Base64Encrypt()
    elif escolhaMenu == "5":
        InverterTexto()
    elif escolhaMenu == "6":
        Apresentacao()
        print("Cifra De César.\n  \033[1;35mA\033[1;97m) Criptografar.\n  \033[1;35mB\033[1;97m) Descriptografar.\n")
        CDCEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
        if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
            CifraDeCesarEncrypt()
        elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
            CifraDeCesarDecrypt()
        else:
            print("\033[1;91mOpção inválida tente novamente.\033[1;97m")
            sleep(3)
            Apresentacao()
            print("Cifra De César.\n  \033[1;35mA\033[1;97m) Criptografar.\n  \033[1;35mB\033[1;97m) Descriptografar.\n")
            CDCEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
            if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
                CifraDeCesarEncrypt()
            elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
                CifraDeCesarDecrypt()
            else:
                print("\033[1;91mVocê inseriu um opção inválida pela segunda vez, voltando para o menu inicial.\033[1;97m")
                sleep(3)
                Menu()
    elif escolhaMenu == "7":
        Apresentacao()
        print("Hexadecimal.\n  \033[1;35mA\033[1;97m) Criptografar.\n  \033[1;35mB\033[1;97m) Descriptografar.\n")
        HexadecimalEncryptOrDecrypt = input("    \033[1;31m~~>\033[1;97m ")
        if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
            HexadecimalEncrypt()
        elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
            HexadecimalDecrypt()
        else:
            print("\033[1;91mOpção inválida tente novamente.\033[1;97m")
            sleep(3)
            Apresentacao()
            print("Hexadecimal.\n  \033[1;35mA\033[1;97m) Criptografar.\n  \033[1;35mB\033[1;97m) Descriptografar.\n")
            HexadecimalEncryptOrDecrypt = input("   \033[1;31m~~>\033[1;97m ")
            if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
                HexadecimalEncrypt()
            elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
                HexadecimalDecrypt()
            else:
                print("\033[1;91mVocê inseriu um opção inválida pela segunda vez, voltando para o menu inicial.\033[1;97m")
                sleep(3)
                Menu()
    elif escolhaMenu == "00":
        exit(1)
    else:
        print("\033[1;91mVocê inseriu uma opção inválida. Por favor insira uma das opções.\033[1;97m")
        sleep(2)
        Menu()

Menu()
