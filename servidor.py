#!/usr/bin/env python3.7
import socket
from passlib.hash import argon2
from Crypto.Cipher import AES
import random
import string
from hashlib import new
import csv
from signal import signal, SIGINT
from sys import exit
"""¡Encriptacion Simetrica firmada! Creada Por: Arturo Melgarejo Galindo"""



class Alertas:
    def info(self, log):
        return print("\033[94m" + "[+] Info: " + log + "\033[0m")
        pass
    def warning(self, log):
        return print("\033[93m" + "[+] Importante: " + log + "\033[0m")
        pass
    def error(self, log):
        return print("\033[91m" + "[+] Error: " + log + "\033[0m")
        pass
    def alerta_seguridad(self, log):
        return print("\033[91m" + "[+] Alerta de seguridad/error: " + log + "\033[0m")


def rwiv(md5hash, mode):
    with open("crypto/IV", mode) as archivo:
        if mode == "wb":
            return archivo.write(md5hash)
        else:
            return archivo.read(16)


def handler(signal_received, frame):
    print(' CTRL+C DETECTADO ADIOS MI CAPITAN :)')
    exit(0)


if __name__ == '__main__':
    signal(SIGINT, handler)


def mandar_contenido(contenido="Mensaje Por defecto"):
    if len(col[2]) <= 0:
        alert.error("¡Estamos intentando mandar un mensaje encriptado sin tener al host en las keys!")
        pass
    a = encriptar(contenido, col[1])


def escribir_csv(lista):
    with open('crypto/hosts.csv', 'a+', newline='') as archivo:
        escribir = csv.writer(archivo, delimiter=";")
        return escribir.writerow(lista)


def buscarcsv(host):
    global col
    with open('crypto/hosts.csv') as archivo:
        csvreader = csv.reader(archivo, delimiter=';')
        contador = 0
        for col in csvreader:
            if col[0] == host:
                alert.info("Host encontrado en lista de claves-hosts")
                return
        alert.warning("Primer Intercambio de clave simetrica (AES)")
        col[0] = ""
        return False


def passgenerator(stringLength):
    # generador de pass aleatoria // password ascii generator
    letras = string.ascii_letters
    return ''.join(random.choice(letras) for i in range(stringLength))


def encriptar(mensaje):
    cifrado = AES.new(col[1], AES.MODE_CBC, Init_Vector)
    """Encriptamos el texto con el IV, CBC & k (key)"""
    return cifrado.encrypt(mensaje)


def desdencriptar(mensaje):
    clave = AES.new(col[1], AES.MODE_CBC, Init_Vector)
    """Desencriptamos, con la key guardada, y el Init Vector"""
    return clave.decrypt(mensaje)

def unpack_func(pa):
    code = pa[0:1]
    longitud_men = pa[1:2]
    resp = pa[2:longitud_men[0]+2]
    longitud_pad = pa[longitud_men[0]+2:longitud_men[0]+3]
    hash = pa[longitud_men[0]+3:len(pa)]
    resp = desdencriptar(resp)
    resp = resp[0:len(resp)-longitud_pad[0]]
    if argon2.verify(resp, hash):
        alert.warning('Se ha comprobado la integridad del paquete recibido')
    else:
        alert.alerta_seguridad("¡Atencion no se ha verificado la integridad del mensaje, alguien puede estar haciendo un mitm! Se reportara al Administrador del servidor")


def main():
    global alert
    global Init_Vector
    max_hosts = 5  # archivo de configuracion decide los maximos hosts de la red que van a conectarse // Max host from config file
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    alert = Alertas()
    alert.info("Intentando Bindear el puerto 2876")
    s.bind((socket.gethostname(), 2876))
    s.listen(max_hosts)
    while True:
        paquete, address = s.accept()
        resultado = buscarcsv(address[0])
        if len(col[0]) <= 0:  # en caso de que el host no este en nuestras columnas de cifrados,
            # le mandamos el header de cifrado y el host ya tomara decision
            alert.info("Intercambio de claves con el host: " + address[0])
            header = "ZEXjNHTJrgo12xcVWrdGvvvHfoHzSv"  # in case of host isn't in csv columns of ciphers
            key = bytes(passgenerator(32), "utf-8")
            lista = [address[0], key.decode("utf-8"), "Client"]
            escribir_csv(lista)
            iv = new("md5", col[2].encode("utf-8"))
            IV = iv.hexdigest()
            iv = iv.digest()
            alert.info("IV vector: " + IV)
            rwiv(iv, "wb")
            # print to logs the key exchange is going to be
            paquete.send(bytes(header, "utf-8") + key)  # we send header + cipher key
            paquete.close()
        else:
            paquete.send(b"Hola buenos dias")
            Init_Vector = rwiv("", "rb")
            contenido = paquete.recv(1024)
            unpack_func(contenido)


main()
