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
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Md5?(s/N) ")
    if refazer == "s" or refazer =="S":
        Md5Encrypt()
    else:
        Menu()

def Sha256Encrypt():
    Apresentacao()
    stringSha256 = input("Digite o texto que deseja criptografar em Sha256: ")
    resultadoSha256 = hashlib.sha256(stringSha256.encode())
    print("Resultado: " + resultadoSha256.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Sha256?(s/N) ")
    if refazer == "s" or refazer =="S":
        Sha256Encrypt()
    else:
        Menu()

def Sha512Encrypt():
    Apresentacao()
    stringSha512 = input("Digite o texto que deseja criptografar em Sha512: ")
    resultadoSha512 = hashlib.sha512(stringSha512.encode())
    print ("Resultado: " + resultadoSha512.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Sha512?(s/N) ")
    if refazer == "s" or refazer =="S":
        Sha512Encrypt()
    else:
        Menu()

def Base64Encrypt():
    Apresentacao()
    stringBase64E = input("Digite o texto que deseja criptografar em Base64: ")
    resultadoBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = resultadoBase64E.decode('utf-8')
    print ("Resultado: " + decode)
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Base64?(s/N) ")
    if refazer == "s" or refazer =="S":
        Base64Encrypt()
    else:
        Menu()

def CifraDeCesarEncrypt():
    Apresentacao()
    mensagemE = input("Digite a frase que deseja criptografar: ")
    cifraE = int(input("Digite a chave:\n ~~> "))
    print ("Resultado: ", end="")
    for i in range(len(mensagemE)):
        print(chr(ord(mensagemE[i]) + cifraE), end = "")
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Cifra de Cesar?(s/N) ")
    if refazer == "s" or refazer =="S":
        CifraDeCesarEncrypt()
    else:
        Menu()

def CifraDeCesarDecrypt():
    Apresentacao()
    mensagemD = input("Digite a frase que deseja descriptografar: ")
    cifraD = int(input("Digite a chave: "))
    print ("Resultado: ", end="")
    for i in range(len(mensagemD)):
        resultado = print(chr(ord(mensagemD[i]) - cifraD), end="")
    Vazio()
    sleep(1)
    refazer = input("Deseja descriptografar outra frase em Cifra de Cesar?(s/N) ")
    if refazer == "s" or refazer =="S":
        CifraDeCesarDecrypt()
    else:
        Menu()

def InverterTexto():
    Apresentacao()
    stringInverterTexto = input("Digite o texto que deseja inverter: ")
    print("Resultado: " + stringInverterTexto[::-1])
    Vazio()
    sleep(1)
    refazer = input("Deseja inverter outro texto?(s/N) ")
    if refazer == "s" or refazer =="S":
        InverterTexto()
    else:
        Menu()

def HexadecimalEncrypt():
    Apresentacao()
    stringHexadecimalE = input("Digite o texto que deseja passar para hexadecimal: ")
    ResultadoHexadecimalE = binascii.hexlify(bytes(stringHexadecimalE, "utf-8"))
    ResultadoHexadecimalE = str(ResultadoHexadecimalE).strip("b")
    ResultadoHexadecimalE = ResultadoHexadecimalE.strip("'")
    ResultadoHexadecimalE = re.sub(r'(..)', r'\1 ', ResultadoHexadecimalE).strip()
    print("Resultado: " + ResultadoHexadecimalE)
    Vazio()
    sleep(1)
    refazer = input("Deseja passar outro texto para hexadecimal?(s/N) ")
    if refazer == "s" or refazer =="S":
        HexadecimalEncrypt()
    else:
        Menu()

def HexadecimalDecrypt():
    Apresentacao()
    stringHexadecimalD = input("Digite o texto em hexadecimal que deseja desvendar: ")
    ResultadoHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8')
    print("Resultado: " + ResultadoHexadecimalD)
    Vazio()
    sleep(1)
    refazer = input("Deseja desvendar outro texto em hexadecimal(s/N) ")
    if refazer == "s" or refazer =="S":
        HexadecimalDecrypt()
    else:
        Menu()

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
