#!/usr/bin/env python
#coding: utf-8

import hashlib
from base64 import b64encode, b64decode
import codecs
import binascii
import re
from time import sleep
import sys
import os
from platform import python_version

if sys.version_info[0] < 3:
    version = python_version()
    print("Você está usando o python na versão %s ela é inferior ao python3 em diante." %(version))
    print("Por favor execute a ferramenta utilizando python3 em diante")

sistemaOperacional = input("Olá, você está utilizando Linux ou Windows? ")
def clear():
    if (sistemaOperacional == "Linux") or (sistemaOperacional == "linux"):
        linuxClear = os.system('clear')
    elif (sistemaOperacional == "Windows") or (sistemaOperacional == "windows"):
        windowsClear = os.system('cls')

def Vazio():
    print(" ")

def Apresentacao():
    clear()
    print ("""
    \t\t    _/_/_/    _/              _/                            _/                      _/
    \t\t   _/    _/        _/_/_/  _/_/_/_/    _/_/    _/  _/_/  _/_/_/_/    _/_/      _/_/_/
    \t\t  _/    _/  _/  _/_/        _/      _/    _/  _/_/        _/      _/_/_/_/  _/    _/
    \t\t_/    _/  _/      _/_/    _/      _/    _/  _/          _/      _/        _/    _/
    \t\t_/_/_/    _/  _/_/_/        _/_/    _/_/    _/            _/_/    _/_/_/    _/_/_/
    \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t version: 1.1.0
    """)

def Md5Encrypt():
    Apresentacao()
    stringMd5 = input("Digite o texto que deseja criptografar em Md5: ")
    resultadoMd5 = hashlib.md5(stringMd5.encode())
#    Vazio()
    print ("Resultado: " + resultadoMd5.hexdigest())

def Sha256Encrypt():
    Apresentacao()
    stringSha256 = input("Digite o texto que deseja criptografar em Sha256: ")
    resultadoSha256 = hashlib.sha256(stringSha256.encode())
    #Vazio()
    print("Resultado: " + resultadoSha256.hexdigest())

def Sha512Encrypt():
    Apresentacao()
    stringSha512 = input("Digite o texto que deseja criptografar em Sha512: ")
    resultadoSha512 = hashlib.sha512(stringSha512.encode())
#    Vazio()
    print ("Resultado: " + resultadoSha512.hexdigest())

def Base64Encrypt():
    Apresentacao()
    stringBase64E = input("Digite o texto que deseja criptografar em Base64: ")
    resultadoBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = resultadoBase64E.decode('utf-8')
#    Vazio()
    print ("Resultado: " + decode)

def InverterTexto():
    Apresentacao()
    stringInverterTexto = input("Digite o texto que deseja inverter: ")
#    Vazio()
    print("Resultado: " + stringInverterTexto[::-1])

def Menu():
    Apresentacao()
    print("Opções disponíveis:\n1 - Md5.\n2 - Sha256.\n3 - Sha512.\n4 - Base64.\n5 - Inverter Texto.\n")
    escolhaMenu = input("Escolha que tipo de criptografia deseja usar: ")
    if escolhaMenu == "1": #Criptografia em Md5.
        Md5Encrypt()
    if escolhaMenu == "2":
        Sha256Encrypt()
    if escolhaMenu == "3":
        Sha512Encrypt()
    if escolhaMenu == "4":
        Base64Encrypt()
    if escolhaMenu == "5":
        InverterTexto()

Menu()
