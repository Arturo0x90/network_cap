#!/usr/bin/env python3.7
import socket
from passlib.hash import argon2
from Crypto.Cipher import AES
import json
from hashlib import new
from os import urandom
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


class Codigos_mensajes:
    exchange_key = bytes("ZEXjNHTJrgo12xcVWrdGvvvHfoHzSv", "utf-8")
    codes = {
        "estoy_vivo" : b"\x99",
        "informacion" : b"\x00",
        "alerta" : b"\x01",
    }
    pass

def tob(a):
    return bytes(a, 'utf-8')


def mandar_contenido(contenidoi=b"1234567891234567", code=b"\x00"):
    """Estaba muy dormido cuando lo hice, lo solucione asi y ya XD, pero bueno, la estructura funciona a la perfeccion y el sistema de firmado"""
    contenido = contenidoi
    if len(info[0]) <= 0:
        return alert.error("No se ha encontrado ningun host en las claves")
    if len(contenido) < 16:
        padding2 = 16-len(contenido)
        contenido = contenido + urandom(padding2)
        a = True
    padding = len(contenido) % 16
    if padding == 0:
        pass
    else:
        contenido = contenido + urandom(16-padding)
        a = False
    if a:
        padding = padding2
    else:
        padding = 16-padding
    alert.info("Bloque de cifrado Corregido.")
    a = encriptar(contenido)
    #STRUCT mensaje = mensaje + relleno
    #STRUCT = code + length(mensaje) + mensaje + len(randompadding) + checksum
    argon = argon2.hash(contenidoi)
    s.send(code + bytes([len(a)]) + a + bytes([padding]) + bytes(argon, "utf-8"))


def encriptar(mensaje):
    cifrado = AES.new(key, AES.MODE_CBC, Init_Vector)
    return cifrado.encrypt(mensaje)  # mensaje cifrado


def desdencriptar(mensaje):
    clave = AES.new(key, AES.MODE_CBC, Init_Vector)
    """Desencriptamos, con la key guardada, y el Init Vector"""
    return clave.decrypt(mensaje)

def rwiv(md5hash, mode):
    with open("crypto/IV", mode) as archivo:
        if mode == "wb":
            return archivo.write(md5hash)
        else:
            return archivo.read(16)
def leer_json():
    with open('crypto/AES.json') as archivo_json:  # abrimos el json
        datos = json.load(archivo_json)  # abrimos el archivo como json
        return datos['key'], datos['servidor'], datos['nombre'], datos['Init Vector']


def escribir_json(keyiv, host, iv):
    with open('crypto/AES.json', 'w') as archivo_json:
        data = {}
        data['key'] = keyiv  # Escribimos la clave en el json
        data['servidor'] = host # Escribimos el host en el registro
        data['nombre'] = info[2] or "Client"
        data['Init Vector'] = iv
        json.dump(data, archivo_json)


def conectar_servidor():
    global s
    global alert
    global info
    global Init_Vector
    global key
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    info = leer_json()
    host = socket.gethostname()
    alert = Alertas()
    code = Codigos_mensajes()
    if len(info[1]) > 1:
        host = info[1]
    alert.info("Intentando conectar al servidor: " + host)
    s.connect((host, 2876))
    mensaje = ''
    """Init vector, No necesita ser para nada seguro, simplemente afecta a la primera rotacion de bits, lo importante es la key, el IV se hace alrededor de algo que identifique al cliente"""
    while True:
        msg = s.recv(1024)
        if msg.startswith(code.exchange_key):  # si nos llega el header del 1º intercambio de clave
            msg = msg.replace(code.exchange_key, b"")
            if not info[0]:  # escribir_json(mensaje)
                iv = new("md5", info[2].encode("utf-8"))
                IV = iv.hexdigest()
                iv = iv.digest()
                alert.info("IV vector: " + IV)
                alert.warning("Guardando la key AES & IV")
                k = msg.decode('utf-8')
                escribir_json(k[0:32], host, IV)
                rwiv(iv, "wb")
            else:
                alert.alerta_seguridad("¡ATENCION! SE HA INTENTADO HACER UN INTERCAMBIO DE CLAVES, PERO YA HAY CLAVES EXISTENTES EN EL CLIENTE, \nSE REPORTARA AL ADMINISTRADOR DEL SERVIDOR.\n")
                """En caso de que se pretenda un intercambio de clave erroneo, se informara,
                 ya que puede ser un atacante mitm pretendiendo un intercambio de claves"""
        else:
            key = info[0]
            Init_Vector = rwiv("", "rb")
            inputs = input("\033[94m" + "Prueba de concepto! Envia mensajes Firmados por Argon2 al servidor $ " + "\033[0m")
            mandar_contenido(contenidoi=bytes(inputs, "utf-8"))
            exit("Adios")
            #alert.info("Paquete del servidor Recibido: ", desdencriptar(msg))
        break


conectar_servidor()
