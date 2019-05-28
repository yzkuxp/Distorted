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
    print("Você está usando o python na versão %s ela é inferior ao python3 em diante." %(version))
    print("Por favor execute a ferramenta utilizando python3 em diante")
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
    print ("""
   ___________________________________________
  |                                           |
  |    ____  _     _           _         _    |
  |   |    \|_|___| |_ ___ ___| |_ ___ _| |   |
  |   |  |  | |_ -|  _| . |  _|  _| -_| . |   |
  |   |____/|_|___|_| |___|_| |_| |___|___|   |
  |                By: yzkuxp                 |
  |                                           |
  |___________________________________________|
    """)

def Md5Encrypt():
    Apresentacao()
    stringMd5 = input("Digite o texto que deseja criptografar em Md5: ")
    resultadoMd5 = hashlib.md5(stringMd5.encode())
    print ("Resultado: " + resultadoMd5.hexdigest())

def Sha256Encrypt():
    Apresentacao()
    stringSha256 = input("Digite o texto que deseja criptografar em Sha256: ")
    resultadoSha256 = hashlib.sha256(stringSha256.encode())
    print("Resultado: " + resultadoSha256.hexdigest())

def Sha512Encrypt():
    Apresentacao()
    stringSha512 = input("Digite o texto que deseja criptografar em Sha512: ")
    resultadoSha512 = hashlib.sha512(stringSha512.encode())
    print ("Resultado: " + resultadoSha512.hexdigest())

def Base64Encrypt():
    Apresentacao()
    stringBase64E = input("Digite o texto que deseja criptografar em Base64: ")
    resultadoBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = resultadoBase64E.decode('utf-8')
    print ("Resultado: " + decode)

def CifraDeCesarEncrypt():
    Apresentacao()
    mensagemE = input("Digite a frase que deseja criptografar: ")
    cifraE = int(input("Digite a chave:\n ~~> "))
    for i in range(len(mensagemE)):
        print(chr(ord(mensagemE[i]) + cifraE), end="")

def CifraDeCesarDecrypt():
    Apresentacao()
    mensagemD = input("Digite a frase que deseja descriptografar: ")
    cifraD = int(input("Digite a chave: "))
    for i in range(len(mensagemD)):
        print(chr(ord(mensagemD[i]) - cifraD), end="")


def InverterTexto():
    Apresentacao()
    stringInverterTexto = input("Digite o texto que deseja inverter: ")
    print("Resultado: " + stringInverterTexto[::-1])

def HexadecimalEncrypt():
    Apresentacao()
    stringHexadecimalE = input("Digite o texto que deseja passar para hexadecimal: ")
    ResultadoHexadecimalE = binascii.hexlify(bytes(stringHexadecimalE, "utf-8"))
    ResultadoHexadecimalE = str(ResultadoHexadecimalE).strip("b")
    ResultadoHexadecimalE = ResultadoHexadecimalE.strip("'")
    ResultadoHexadecimalE = re.sub(r'(..)', r'\1 ', ResultadoHexadecimalE).strip()
    print("Resultado: " + ResultadoHexadecimalE)

def HexadecimalDecrypt():
    Apresentacao()
    stringHexadecimalD = input("Digite o texto em hexadecimal que deseja desvendar: ")
    ResultadoHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8')
    print("Resultado: " + ResultadoHexadecimalD)

def Menu():
    Apresentacao()
    print("Opções disponíveis:\n  1 - Md5.\n  2 - Sha256.\n  3 - Sha512.\n  4 - Base64.\n  5 - Inverter Texto.\n  6 - ENCRYPT/DECRYPT Cifra de César.\n  7 - ENCRYPT/DECRYPT Hexadecimal.\n  00 - Exit.\n")
    escolhaMenu = input("Qual das opções você gostaria de utilizar:\n ~~> ")
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
        print("Cifra De César.\n  A) Criptografar.\n  B) Descriptografar.\n")
        CDCEncryptOrDecrypt = input("Qual das opções você gostaria de utilizar:\n ~~> ")
        if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
            CifraDeCesarEncrypt()
        elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
            CifraDeCesarDecrypt()
    elif escolhaMenu == "7":
        Apresentacao()
        print("Hexadecimal.\n  A) Criptografar.\n  B) Descriptografar.\n")
        HexadecimalEncryptOrDecrypt = input("Qual das opções você gostaria de utilizar:\n ~~> ")
        if (HexadecimalEncryptOrDecrypt == "A") or (HexadecimalEncryptOrDecrypt == "a"):
            HexadecimalEncrypt()
        elif (HexadecimalEncryptOrDecrypt == "B") or (HexadecimalEncryptOrDecrypt == "b"):
            HexadecimalDecrypt()
    elif escolhaMenu == "00":
        exit(1)
    else:
        print("Você inseriu uma opção inválida. Por favor insira uma das opções.")
        sleep(2)
        Menu()

Menu()
