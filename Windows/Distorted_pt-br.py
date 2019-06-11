# Ferramenta feita em python por mim mesmo para criptografar o seu texto.
# Opções de Criptografia: Md5, Sha256, Sha512, Base64, Inverter Texto, Cifra de Cesas e Hexadecimal.
# OBS: A ferramenta ainda está em desenvolvimento. E pode ter algum bug, ou algum recurso faltando.
# Feito por: yzkuxp
# Aproveite ^^

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
    versao = python_version()
    print("Você está usando o python na versão %s ela é inferior ao python3 em diante." %(versao))
    print("Por favor execute a ferramenta utilizando python3 em diante")
    sleep(3)
    exit(1)

def Limpar():
    os.system('cls')

def Vazio():
    print("    ")

def Apresentacao():
    Limpar()
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

def Md5Criptografar():
    Apresentacao()
    stringMd5 = input("\nDigite o texto que deseja criptografar em Md5: ")
    resultadoMd5 = hashlib.md5(stringMd5.encode())
    print ("Resultado: " + resultadoMd5.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Md5?(s/N) ")
    if refazer == "s" or refazer =="S":
        Md5Criptografar()
    else:
        Menu()

def Sha256Criptografar():
    Apresentacao()
    stringSha256 = input("\nDigite o texto que deseja criptografar em Sha256: ")
    resultadoSha256 = hashlib.sha256(stringSha256.encode())
    print("Resultado: " + resultadoSha256.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Sha256?(s/N) ")
    if refazer == "s" or refazer =="S":
        Sha256Criptografar()
    else:
        Menu()

def Sha512Criptografar():
    Apresentacao()
    stringSha512 = input("\nDigite o texto que deseja criptografar em Sha512: ")
    resultadoSha512 = hashlib.sha512(stringSha512.encode())
    print ("Resultado: " + resultadoSha512.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Sha512?(s/N) ")
    if refazer == "s" or refazer =="S":
        Sha512Criptografar()
    else:
        Menu()

def Base64Criptografar():
    Apresentacao()
    stringBase64E = input("\nDigite o texto que deseja criptografar em Base64: ")
    resultadoBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = resultadoBase64E.decode('utf-8')
    print ("Resultado: " + decode)
    Vazio()
    sleep(1)
    refazer = input("Deseja fazer outra criptografia em Base64?(s/N) ")
    if refazer == "s" or refazer == "S":
        Base64Criptografar()
    else:
        Menu()

def CifraDeCesarCriptografar():
    Apresentacao()
    mensagemE = input("\nDigite a frase que deseja criptografar: ")
    cifraE = int(input("Digite a chave: "))
    print ("Resultado: ", end = "")
    for i in range(len(mensagemE)):
        print(chr(ord(mensagemE[i]) + cifraE), end = "")
    Vazio()
    sleep(1)
    refazer = input("\nDeseja fazer outra criptografia em Cifra de Cesar?(s/N) ")
    if refazer == "s" or refazer == "S":
        CifraDeCesarCriptografar()
    else:
        Menu()

def CifraDeCesarDescriptografar():
    Apresentacao()
    mensagemD = input("\nDigite a frase que deseja descriptografar: ")
    cifraD = int(input("Digite a chave: "))
    print ("Resultado: ", end="")
    for i in range(len(mensagemD)):
        resultado = print(chr(ord(mensagemD[i]) - cifraD), end="")
    Vazio()
    sleep(1)
    refazer = input("\nDeseja descriptografar outra frase em Cifra de Cesar?(s/N) ")
    if refazer == "s" or refazer =="S":
        CifraDeCesarDescriptografar()
    else:
        Menu()

def InverterTexto():
    Apresentacao()
    stringInverterTexto = input("\nDigite o texto que deseja inverter: ")
    print("Resultado: " + stringInverterTexto[::-1])
    Vazio()
    sleep(1)
    refazer = input("Deseja inverter outro texto?(s/N) ")
    if refazer == "s" or refazer =="S":
        InverterTexto()
    else:
        Menu()

def HexadecimalCriptografar():
    Apresentacao()
    stringHexadecimalE = input("\nDigite o texto que deseja passar para hexadecimal: ")
    ResultadoHexadecimalE = binascii.hexlify(bytes(stringHexadecimalE, "utf-8"))
    ResultadoHexadecimalE = str(ResultadoHexadecimalE).strip("b")
    ResultadoHexadecimalE = ResultadoHexadecimalE.strip("'")
    ResultadoHexadecimalE = re.sub(r'(..)', r'\1 ', ResultadoHexadecimalE).strip()
    print("Resultado: " + ResultadoHexadecimalE)
    Vazio()
    sleep(1)
    refazer = input("Deseja passar outro texto para hexadecimal?(s/N) ")
    if refazer == "s" or refazer =="S":
        HexadecimalCriptografar()
    else:
        Menu()

def HexadecimalDescriptografar():
    Apresentacao()
    stringHexadecimalD = input("\nDigite o texto em hexadecimal que deseja desvendar: ")
    ResultadoHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8')
    print("Resultado: " + ResultadoHexadecimalD)
    Vazio()
    sleep(1)
    refazer = input("Deseja desvendar outro texto em hexadecimal(s/N) ")
    if refazer == "s" or refazer =="S":
        HexadecimalDescriptografar()
    else:
        Menu()

def Menu():
    Apresentacao()
    print("""
    \t [+] Opções disponíveis:
    \t  1. CRIPTOGRAFAR - Md5.
    \t  2. CRIPTOGRAFAR - Sha256.
    \t  3. CRIPTOGRAFAR - Sha512.
    \t  4. CRIPTOGRAFAR - Base64.
    \t  5. CRIPTOGRAFAR - Inverter Texto.
    \t  6. CRIPTOGRAFAR/DESCRIPTOGRAFAR - Cifra de César.
    \t  7. CRIPTOGRAFAR/DESCRIPTOGRAFAR - Hexadecimal.
    \t  q. Exit.\n""")
    escolhaMenu = input("   ~~> ")
    if escolhaMenu == "1":
        Md5Criptografar()
    elif escolhaMenu == "2":
        Sha256Criptografar()
    elif escolhaMenu == "3":
        Sha512Criptografar()
    elif escolhaMenu == "4":
        Base64Criptografar()
    elif escolhaMenu == "5":
        InverterTexto()
    elif escolhaMenu == "6":
        Apresentacao()
        print("""\t [+] Cifra De César.
          A) Criptografar.
          B) Descriptografar.\n""")
        CDCCriptografarOuDescriptografar = input("   ~~> ")
        if (CDCCriptografarOuDescriptografar == "A") or (CDCCriptografarOuDescriptografar == "a"):
            CifraDeCesarCriptografar()
        elif (CDCCriptografarOuDescriptografar == "B") or (CDCCriptografarOuDescriptografar == "b"):
            CifraDeCesarDescriptografar()
        else:
            print("Opção inválida tente novamente.")
            sleep(3)
            Apresentacao()
            print("""\t [+] Cifra De César.
              A) Criptografar.
              B) Descriptografar.\n""")
            CDCCriptografarOuDescriptografar = input("   ~~> ")
            if (CDCCriptografarOuDescriptografar == "A") or (CDCCriptografarOuDescriptografar == "a"):
                CifraDeCesarCriptografar()
            elif (CDCCriptografarOuDescriptografar == "B") or (CDCCriptografarOuDescriptografar == "b"):
                CifraDeCesarDescriptografar()
            else:
                print("Você inseriu um opção inválida pela segunda vez, voltando para o menu inicial.")
                sleep(3)
                Menu()
    elif escolhaMenu == "7":
        Apresentacao()
        print("""\t [+] Hexadecimal.
          A) Criptografar.
          B) Descriptografar.\n""")
        HexadecimalCriptografarOuDescriptografar = input("    ~~> ")
        if (HexadecimalCriptografarOuDescriptografar == "A") or (HexadecimalCriptografarOuDescriptografar == "a"):
            HexadecimalCriptografar()
        elif (HexadecimalCriptografarOuDescriptografar == "B") or (HexadecimalCriptografarOuDescriptografar == "b"):
            HexadecimalDescriptografar()
        else:
            print("Opção inválida tente novamente.")
            sleep(3)
            Apresentacao()
            print("""\t [+] Hexadecimal.
              A) Criptografar.
              B) Descriptografar.\n""")
            HexadecimalCriptografarOuDescriptografar = input("   ~~> ")
            if (HexadecimalCriptografarOuDescriptografar == "A") or (HexadecimalCriptografarOuDescriptografar == "a"):
                HexadecimalCriptografar()
            elif (HexadecimalCriptografarOuDescriptografar == "B") or (HexadecimalCriptografarOuDescriptografar == "b"):
                HexadecimalDescriptografar()
            else:
                print("Você inseriu um opção inválida pela segunda vez, voltando para o menu inicial.")
                sleep(3)
                Menu()
    elif escolhaMenu == "q" or escolhaMenu == "Q":
        exit(1)
    else:
        print("Você inseriu uma opção inválida. Por favor insira uma das opções.")
        sleep(3)
        Menu()

Menu()
