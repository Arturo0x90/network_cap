#!/usr/bin/env python3.7
import socket
from Crypto.Cipher import AES
import random
import string
import struct
import csv
import threading
from signal import signal, SIGINT
from sys import exit
def handler(signal_received, frame):
    print(' CTRL+C DETECTADO ADIOS MI CAPITAN :)')
    exit(0)
if __name__ == '__main__':
    signal(SIGINT, handler)
def mandar_contenido(hostkeys, contenido="Mensaje Por defecto"):
    if len(hostkeys[2]) <= 0:
        print("¡Estamos intentando mandar un mensaje encriptado sin tener al host en las keys!")
        pass
    a = encriptar(contenido, hostkeys[1])
    return a, hostkeys[1], contenido, hostkeys[2]
def escribir_csv(lista):
        with open('crypto/hosts.csv', 'a+', newline='') as archivo:
            escribir = csv.writer(archivo, delimiter=";")
            escribir.writerow(lista)
def buscarcsv(host):
        with open('crypto/hosts.csv') as archivo:
            csvreader = csv.reader(archivo, delimiter=';')
            contador = 0
            for col in csvreader:
                if len(col[0]) <= 0:
                    print("Primer Host de intercambio")
                    return False, 1
                if col[0] == host:
                    print("Host encontrado en lista de claves-hosts")
                    return col[0], col[1], col[2]
            print("No se ha encontrado el host indicado en nuestras columnas")
            return False, 2
def passgenerator(stringLength):
        #generador de pass aleatoria // password ascii generator
        letras = string.ascii_letters
        return ''.join(random.choice(letras) for i in range(stringLength))
def encriptar(mensaje, key):
        clave = AES.new(key)
        return clave.encrypt(mensaje)
def desdencriptar(mensaje, key):
        clave = AES.new(key)
        return clave.decrypt(mensaje)
def enviar():
        max_hosts = 5 #archivo de configuracion decide los maximos hosts de la red que van a conectarse // Max host from config file
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((socket.gethostname(), 2872))
        s.listen(max_hosts)
        while True:
                paquete, address = s.accept()
                Aes_keys = True #borrar despues de crear las columnas de csv
                print("successful connection From -> {}", address[0])
                hostkeys = buscarcsv(address[0])
                if hostkeys[0] == False: #en caso de que el host no este en nuestras columnas de cifrados,
                        #le mandamos el header de cifrado y el host ya tomara decision
                        header = "ZEXjNHTJrgo12xcVWrdGvvvHfoHzSv" #in case of host isn't in csv columns of ciphers
                        key = bytes(passgenerator(32), "utf-8")
                        lista = [address[0], key.decode("utf-8"), "Client"]
                        escribir_csv(lista)
                        print("Key exchange from -> ", address[0], "Key-content -> ", key.decode("utf-8")) #print to logs the key exchange is going to be
                        paquete.send(bytes(header, "utf-8") + key) #we send header + cipher key
                        paquete.close()
                else:
                        tracker = mandar_contenido(hostkeys, contenido=passgenerator(16))
                        paquete.send(tracker[0])
enviar()
