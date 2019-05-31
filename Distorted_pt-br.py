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

branco = '\033[1;97m'
vermelho = '\033[1;31m'
magneta = '\033[1;35m'
ciano = '\033[1;36m'


if sys.version_info[0] < 3:
    versao = python_version()
    print("\033[1;91mVocê está usando o python na versão %s ela é inferior ao python3 em diante.\033[1;97m" %(versao))
    print("\033[1;91mPor favor execute a ferramenta utilizando python3 em diante\033[1;97m")
    sleep(3)
    exit(1)

sistemaOperacional = input("\nOlá, qual sistema operacional você está utlizando?\n  A) Linux.\n  B) Windows.\n\n ~~> ")
def LimparDeNovo():
    print ("Opção inválida. Insira uma opção válida.")
    sleep(2)
    sistemaOperacional = sistemaOperacional = input("\n\nOlá, qual sistema operacional você está utlizando?\n  A) Linux.\n  B) Windows.\n\n ~~> ")
    if (sistemaOperacional == "A") or (sistemaOperacional == "a"):
        linuxClear = os.system('clear')
    elif (sistemaOperacional == "B") or (sistemaOperacional == "b"):
        windowsClear = os.system('cls')
    else:
        LimparDeNovo()
def Limpar():
    if (sistemaOperacional == "A") or (sistemaOperacional == "a"):
        linuxClear = os.system('clear')
    elif (sistemaOperacional == "B") or (sistemaOperacional == "b"):
        windowsClear = os.system('cls')
    else:
        LimparDeNovo()

def Vazio():
    print("    ")

def Apresentacao():
    Limpar()
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

def Md5Criptografar():
    Apresentacao()
    stringMd5 = input("\n\033[1;36mDigite o texto que deseja criptografar em Md5\033[1;97m: ")
    resultadoMd5 = hashlib.md5(stringMd5.encode())
    print ("\033[1;36mResultado\033[1;97m: " + resultadoMd5.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Md5?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Md5Criptografar()
    else:
        Menu()

def Sha256Criptografar():
    Apresentacao()
    stringSha256 = input("\n\033[1;36mDigite o texto que deseja criptografar em Sha256\033[1;97m: ")
    resultadoSha256 = hashlib.sha256(stringSha256.encode())
    print("\033[1;36mResultado\033[1;97m: " + resultadoSha256.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Sha256?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Sha256Criptografar()
    else:
        Menu()

def Sha512Criptografar():
    Apresentacao()
    stringSha512 = input("\n\033[1;36mDigite o texto que deseja criptografar em Sha512\033[1;97m: ")
    resultadoSha512 = hashlib.sha512(stringSha512.encode())
    print ("\033[1;36mResultado\033[1;97m: " + resultadoSha512.hexdigest())
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Sha512?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Sha512Criptografar()
    else:
        Menu()

def Base64Criptografar():
    Apresentacao()
    stringBase64E = input("\n\033[1;36mDigite o texto que deseja criptografar em Base64\033[1;97m: ")
    resultadoBase64E = b64encode(stringBase64E.encode('utf-8'))
    decode = resultadoBase64E.decode('utf-8')
    print ("\033[1;36mResultado\033[1;97m: " + decode)
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja fazer outra criptografia em Base64?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        Base64Criptografar()
    else:
        Menu()

def CifraDeCesarCriptografar():
    Apresentacao()
    mensagemE = input("\n\033[1;36mDigite a frase que deseja criptografar\033[1;97m: ")
    cifraE = int(input("\033[1;36mDigite a chave\033[1;97m: "))
    print ("\033[1;36mResultado\033[1;97m: ", end="")
    for i in range(len(mensagemE)):
        print(chr(ord(mensagemE[i]) + cifraE), end = "")
    Vazio()
    sleep(1)
    refazer = input("\n\033[1;31mDeseja fazer outra criptografia em Cifra de Cesar?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        CifraDeCesarCriptografar()
    else:
        Menu()

def CifraDeCesarDescriptografar():
    Apresentacao()
    mensagemD = input("\n\033[1;36mDigite a frase que deseja descriptografar\033[1;97m: ")
    cifraD = int(input("\033[1;36mDigite a chave\033[1;97m: "))
    print ("\033[1;36mResultado\033[1;97m: ", end="")
    for i in range(len(mensagemD)):
        resultado = print(chr(ord(mensagemD[i]) - cifraD), end="")
    Vazio()
    sleep(1)
    refazer = input("\n\033[1;31mDeseja descriptografar outra frase em Cifra de Cesar?(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        CifraDeCesarDescriptografar()
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

def HexadecimalCriptografar():
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
        HexadecimalCriptografar()
    else:
        Menu()

def HexadecimalDescriptografar():
    Apresentacao()
    stringHexadecimalD = input("\n\033[1;36mDigite o texto em hexadecimal que deseja desvendar\033[1;97m: ")
    ResultadoHexadecimalD = bytes.fromhex(stringHexadecimalD).decode('utf-8')
    print("\033[1;36mResultado\033[1;97m: " + ResultadoHexadecimalD)
    Vazio()
    sleep(1)
    refazer = input("\033[1;31mDeseja desvendar outro texto em hexadecimal(s/N)\033[1;97m ")
    if refazer == "s" or refazer =="S":
        HexadecimalDescriptografar()
    else:
        Menu()

def Menu():
    Apresentacao()
    print("""
    \t \033[1;36m[+] \033[1;97mOpções disponíveis:
    \t  \033[1;35m1\033[1;97m. \033[1;35mCRIPTOGRAFAR\033[1;97m - \033[1;36mMd5.
    \t  \033[1;35m2\033[1;97m. \033[1;35mCRIPTOGRAFAR\033[1;97m - \033[1;36mSha256.
    \t  \033[1;35m3\033[1;97m. \033[1;35mCRIPTOGRAFAR\033[1;97m - \033[1;36mSha512.
    \t  \033[1;35m4\033[1;97m. \033[1;35mCRIPTOGRAFAR\033[1;97m - \033[1;36mBase64.
    \t  \033[1;35m5\033[1;97m. \033[1;35mCRIPTOGRAFAR\033[1;97m - \033[1;36mInverter Texto.
    \t  \033[1;35m6\033[1;97m. \033[1;35mCRIPTOGRAFAR/DESCRIPTOGRAFAR \033[1;97m- \033[1;36mCifra de César.
    \t  \033[1;35m7\033[1;97m. \033[1;35mCRIPTOGRAFAR/DESCRIPTOGRAFAR \033[1;97m- \033[1;36mHexadecimal.
    \t  \033[1;35m00\033[1;97m. Exit.\033[1;97m\n""")
    escolhaMenu = input("   \033[1;31m~~>\033[1;97m ")
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
        print("""\t \033[1;36m[+] \033[1;97mCifra De César.
          \033[1;35mA\033[1;97m) \033[1;36mCriptografar.\033[1;97m
          \033[1;35mB\033[1;97m) \033[1;36mDescriptografar.\033[1;97m\n""")
        CDCCriptografarOuDescriptografar = input("   \033[1;31m~~>\033[1;97m ")
        if (CDCCriptografarOuDescriptografar == "A") or (CDCCriptografarOuDescriptografar == "a"):
            CifraDeCesarCriptografar()
        elif (CDCCriptografarOuDescriptografar == "B") or (CDCCriptografarOuDescriptografar == "b"):
            CifraDeCesarDescriptografar()
        else:
            print("\033[1;91mOpção inválida tente novamente.\033[1;97m")
            sleep(3)
            Apresentacao()
            print("""\t \033[1;36m[+] \033[1;97mCifra De César.
              \033[1;35mA\033[1;97m) \033[1;36mCriptografar.\033[1;97m
              \033[1;35mB\033[1;97m) \033[1;36mDescriptografar.\033[1;97m\n""")
            CDCCriptografarOuDescriptografar = input("   \033[1;31m~~>\033[1;97m ")
            if (CDCCriptografarOuDescriptografar == "A") or (CDCCriptografarOuDescriptografar == "a"):
                CifraDeCesarCriptografar()
            elif (CDCCriptografarOuDescriptografar == "B") or (CDCCriptografarOuDescriptografar == "b"):
                CifraDeCesarDescriptografar()
            else:
                print("\033[1;91mVocê inseriu um opção inválida pela segunda vez, voltando para o menu inicial.\033[1;97m")
                sleep(3)
                Menu()
    elif escolhaMenu == "7":
        Apresentacao()
        print("""\t \033[1;36m[+] \033[1;97mHexadecimal.
          \033[1;35mA\033[1;97m) \033[1;36mCriptografar.\033[1;97m
          \033[1;35mB\033[1;97m) \033[1;36mDescriptografar.\033[1;97m\n""")
        HexadecimalCriptografarOuDescriptografar = input("    \033[1;31m~~>\033[1;97m ")
        if (HexadecimalCriptografarOuDescriptografar == "A") or (HexadecimalCriptografarOuDescriptografar == "a"):
            HexadecimalCriptografar()
        elif (HexadecimalCriptografarOuDescriptografar == "B") or (HexadecimalCriptografarOuDescriptografar == "b"):
            HexadecimalDescriptografar()
        else:
            print("\033[1;91mOpção inválida tente novamente.\033[1;97m")
            sleep(3)
            Apresentacao()
            print("""\t \033[1;36m[+] \033[1;97mHexadecimal.
              \033[1;35mA\033[1;97m) \033[1;36mCriptografar.\033[1;97m
              \033[1;35mB\033[1;97m) \033[1;36mDescriptografar\033[1;97m.\n""")
            HexadecimalCriptografarOuDescriptografar = input("   \033[1;31m~~>\033[1;97m ")
            if (HexadecimalCriptografarOuDescriptografar == "A") or (HexadecimalCriptografarOuDescriptografar == "a"):
                HexadecimalCriptografar()
            elif (HexadecimalCriptografarOuDescriptografar == "B") or (HexadecimalCriptografarOuDescriptografar == "b"):
                HexadecimalDescriptografar()
            else:
                print("\033[1;91mVocê inseriu um opção inválida pela segunda vez, voltando para o menu inicial.\033[1;97m")
                sleep(3)
                Menu()
    elif escolhaMenu == "00":
        exit(1)
    else:
        print("\033[1;91mVocê inseriu uma opção inválida. Por favor insira uma das opções.\033[1;97m")
        sleep(3)
        Menu()

Menu()
