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


sistemaOperacional = input("Olá, qual sistema operacional você está utlizando?\n  A) Linux.\n  B) Windows.\n ~~> ")
def clearAgain():
    print ("Opção inválida. Insira uma opção válida.")
    sleep(2)
    sistemaOperacional = sistemaOperacional = input("Olá, qual sistema operacional você está utlizando?\n  A) Linux.\n  B) Windows.\n ~~> ")
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
    \t\t    _/_/_/    _/              _/                            _/                      _/
    \t\t   _/    _/        _/_/_/  _/_/_/_/    _/_/    _/  _/_/  _/_/_/_/    _/_/      _/_/_/
    \t\t  _/    _/  _/  _/_/        _/      _/    _/  _/_/        _/      _/_/_/_/  _/    _/
    \t\t_/    _/  _/      _/_/    _/      _/    _/  _/          _/      _/        _/    _/
    \t\t_/_/_/    _/  _/_/_/        _/_/    _/_/    _/            _/_/    _/_/_/    _/_/_/
    \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t version: 1.1.0
    \t\t\t\t\t   By: yzkuxp
    """)

def Md5Encrypt():
    Apresentacao()
    stringMd5 = input("Digite o texto que deseja criptografar em Md5:\n ~~> ")
    resultadoMd5 = hashlib.md5(stringMd5.encode())
    Vazio()
    print ("Resultado: " + resultadoMd5.hexdigest())

def Sha256Encrypt():
    Apresentacao()
    stringSha256 = input("Digite o texto que deseja criptografar em Sha256:\n ~~> ")
    resultadoSha256 = hashlib.sha256(stringSha256.encode())
    Vazio()
    print("Resultado: " + resultadoSha256.hexdigest())

def Sha512Encrypt():
    Apresentacao()
    stringSha512 = input("Digite o texto que deseja criptografar em Sha512:\n ~~> ")
    resultadoSha512 = hashlib.sha512(stringSha512.encode())
    Vazio()
    print ("Resultado: " + resultadoSha512.hexdigest())

def Base64Encrypt():
    Apresentacao()
    stringBase64E = input("Digite o texto que deseja criptografar em Base64:\n ~~> ")
    resultadoBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = resultadoBase64E.decode('utf-8')
    Vazio()
    print ("Resultado: " + decode)

def CifraDeCesarEncrypt():
    Apresentacao()
    mensagemE = input("Digite a frase que deseja criptografar:\n ~~> ")
    cifraE = int(input("Digite a chave:\n ~~> "))
    for i in range(len(mensagemE)):
        print (chr(ord(mensagemE[i]) + cifraE), end="")
    print ("")
def CifraDeCesarDecrypt():
    Apresentacao()
    mensagemD = input("Digite a frase que deseja descriptografar:\n ~~> ")
    cifraD = int(input("Digite a chave:\n ~~> "))
    for i in range(len(mensagemD)):
        print (chr(ord(mensagemD[i]) - cifraD), end="")
    print ("")

def InverterTexto():
    Apresentacao()
    stringInverterTexto = input("Digite o texto que deseja inverter:\n ~~> ")
    Vazio()
    print("Resultado: " + stringInverterTexto[::-1])

def Menu():
    Apresentacao()
    print("Opções disponíveis:\n  1 - Md5.\n  2 - Sha256.\n  3 - Sha512.\n  4 - Base64.\n  5 - Inverter Texto.\n  6 - Cifra de César.\n  00 - Exit.\n")
    escolhaMenu = input("Qual das opções você gostaria de utilizar:\n ~~> ")
    if escolhaMenu == "1": #Criptografia em Md5.
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
        print("Cifra De César.\n  A) Criptografar.\n  B) Descriptografar.")
        CDCEncryptOrDecrypt = input("Qual das opções você gostaria de utilizar:\n ~~> ")
        if (CDCEncryptOrDecrypt == "A") or (CDCEncryptOrDecrypt == "a"):
            CifraDeCesarEncrypt()
        elif (CDCEncryptOrDecrypt == "B") or (CDCEncryptOrDecrypt == "b"):
            CifraDeCesarDecrypt()
    elif escolhaMenu == "00":
        exit(1)
    else:
        print("Você inseriu uma opção inválida. Por favor insira uma das opções.")
        sleep(2)
        Menu()

Menu()
