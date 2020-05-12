import socket
from passlib.hash import argon2
from Crypto.Cipher import AES
import json
from Crypto import Random
class Alertas:
    def info(self, log):
        return print("\033[94m" + "[+] Info: " + log + "\033[0m")
        pass
    def warning(self, log):
        return print("\033[93m" + "[+] Warning: " + log + "\033[0m")
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


def mandar_contenido(contenido="Defecto", code=b"\x00"):
    if len(info[0]) <= 0:
        return alert.error("No se ha encontrado ningun host en las claves")
    a = encriptar(contenido, info[1])
    mensaje = code + a
    #STRUCT mensaje =
    #STRUCT = length(mensaje) + , 0x00, mensaje + checksum
    s.send(bytes([len(mensaje)]) + mensaje + argon2.hash(contenido))
    print(bytes([len(mensaje)]) + mensaje + argon2.hash(contenido))
    return info[0], contenido, info[1]


def encriptar(mensaje, key):
    b = Random.new().read(AES.block_size)
    cifrado = AES.new(key, AES.MODE_CFB, b)
    return cifrado.encrypt(mensaje)  # mensaje cifrado y de la key para en caso de que no exista una clave->


def desdencriptar(mensaje, key):
    clave = AES.new(key)
    return clave.decrypt(mensaje)


# de ese host, pasarla a la funcion para que pueda trabajar con ella
def leer_json():
    with open('crypto/AES.json') as archivo_json:  # abrimos el json
        datos = json.load(archivo_json)  # abrimos el archivo como json
        return datos['key'], datos['servidor']


def escribir_json(key, host):
    with open('crypto/AES.json', 'w') as archivo_json:
        data = {}
        data['key'] = key  # Escribimos la clave en el json
        data['servidor'] = host # Escribimos el host en el registro
        json.dump(data, archivo_json)


def conectar_servidor():
    global s
    global alert
    global info
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    info = leer_json()
    host = socket.gethostname()
    alert = Alertas()
    code = Codigos_mensajes()
    if len(info[1]) > 1:
        host = info[1]
    alert.info("Intentando conectar al servidor: " + host)
    s.connect((host, 2872))
    mensaje = ''
    while True:
        msg = s.recv(1024)
        if msg.startswith(code.exchange_key):  # si nos llega el header del 1º intercambio de clave
            msg = msg.replace(code.exchange_key, b"")
            if not info[0]:  # escribir_json(mensaje)
                alert.info("Guardando la clave en el registro AES json...")
                escribir_json(msg.decode('utf-8'), host)
            else:
                alert.alerta_seguridad("¡ATENCION! SE HA INTENTADO HACER UN INTERCAMBIO DE CLAVES, PERO YA HAY CLAVES EXISTENTES EN EL CLIENTE, \nSE REPORTARA AL ADMINISTRADOR DEL SERVIDOR.\n")
                """En caso de que se pretenda un intercambio de clave erroneo, se informara,
                 ya que puede ser un atacante mitm pretendiendo un intercambio de claves"""
        else:
            mandar_contenido(info)
            print("Mensaje Recibido:", msg)
            print("Mensaje desencriptado:", desdencriptar(msg, info[0]))
        break


conectar_servidor()
