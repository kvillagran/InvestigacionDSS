#----------------------- RECURSOS Y LIBRERIAS -------------------------
from tabulate import tabulate
import socket
import json
import time
from tqdm import tqdm 

#----------------------- VARIABLES -------------------------
K, cod_psn, num_msj = [], [], 0
cod_psn = [
    ["1234", "0001"], ["1324", "0010"], ["1423", "0011"], ["2134", "0100"],
    ["2314", "0101"], ["2413", "0110"], ["3124", "0111"], ["3214", "1000"],
    ["3412", "1001"], ["4123", "1010"], ["4213", "1011"], ["4312", "1100"],
    ["4321", "1101"], ["2314", "1110"], ["3421", "1111"]
]

#----------------------- FUNCIONES GENERALES -------------------------
def barra_de_carga(proceso, iteraciones, retraso=0.1):
    """Barra de progreso utilizando tqdm"""
    for _ in tqdm(range(iteraciones * 5), desc=proceso):
        time.sleep(retraso)

def leer_json(json_string):
    try:
        data = json.loads(json_string)
        return data["ID"], data["Type"], data["Payload"], data["PSN"]
    except json.JSONDecodeError:
        return None

def respuesta_server(mensaje_emisor, Payload):
    conexion.send(f"{mensaje_emisor}-{Payload}".encode())
    print(f"Mensaje : {Payload}\n")  # Imprime el mensaje recibido del cliente

def bit_a_cadena(binary):
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, 64, 8)).rstrip('\x00')

#----------------------- FUNCIONES BINARIAS -------------------------
def xor_binario(b1, b2):
    return ''.join('0' if b1[i] == b2[i] else '1' for i in range(64))

def binary_not(b):
    return ''.join('1' if bit == '0' else '0' for bit in b)

def rotar_izquierda_bits(b, n):
    return b[n % 64:] + b[:n % 64]

def sustituir_bit(b, p):
    return b[:p] + '0' + b[p+1:]

def xornot(b1, b2):
    return xor_binario(b1, binary_not(b2))

def xor_sust(b1, b2, p):
    return xor_binario(b1, sustituir_bit(b2, p))

def xor_rot(b1, b2, p):
    return xor_binario(b1, rotar_izquierda_bits(b2, p))

#----------------------- FUNCIONES PARA GENERAR LLAVES -------------------------
def tabular(K):
    print(tabulate([[i + 1, valor] for i, valor in enumerate(K)], headers=["Índice", "Key"], tablefmt="grid"))

def generador_llaver(P, Q, S, N):
    barra_de_carga("Generando llaves", N)
    for i in range(1, N + 1):
        if i % 2 == 0:
            Q = xor_binario(Q, S)
            k_n = rotar_izquierda_bits(xor_binario(Q, P), N)
            S = sustituir_bit(xor_binario(S, P), N)
        else:
            P = xor_binario(P, S)
            k_n = rotar_izquierda_bits(xor_binario(P, Q), N)
            S = sustituir_bit(xor_binario(S, Q), N)
        K.append(k_n)
    return tabular(K)

def procesar_mensaje(mensaje, K, psn):
    barra_de_carga("Descifrando Mensaje", 4)
    mensaje_desencriptado_binario = ejecutar_orden_inverso(encontrar_orden(psn, cod_psn), mensaje, K)
    return bit_a_cadena(mensaje_desencriptado_binario)  # Devuelve el mensaje descifrado en texto

#----------------------- FUNCIONES PSN Y DESCIFRADO -------------------------
def invertir_psn(cadena):
    return cadena[::-1]

def ejecutar_orden_inverso(psn, mensaje_encriptado, K):
    inv_psn = invertir_psn(psn)
    for numero in inv_psn:
        if numero == '1':
            mensaje_encriptado = xornot(mensaje_encriptado, K)
        elif numero == '2':
            mensaje_encriptado = xor_sust(mensaje_encriptado, K, int(inv_psn[-1]))
        elif numero == '3':
            mensaje_encriptado = xor_rot(mensaje_encriptado, K, int(inv_psn[0]))
        elif numero == '4':
            mensaje_encriptado = xor_binario(mensaje_encriptado, K)
    return mensaje_encriptado

def encontrar_orden(valor_4bits, cod_psn):
    return next((fila[0] for fila in cod_psn if fila[1] == valor_4bits), None)

#----------------------- CONEXION -------------------------
emisor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
emisor.bind(("localhost", 12345))
emisor.listen(1)
print("Esperando conexión...")

conexion, _ = emisor.accept()

while True:
    mensaje = leer_json(conexion.recv(1024).decode())
    if mensaje:
        id, Type, Payload, psn = mensaje
        if Type == "1111":
            print("El cliente ha cerrado la conexión")
            break
        if Type == "0001":
            K = []
            num_msj = 0  # Reiniciar el contador de mensajes
            P, Q, S, N = Payload
            generador_llaver(P, Q, S, N)
            respuesta_server("FCM", "Se estableció conexión y se crearon las llaves")
        elif K:
            if Type == "0011":
                print(f"Paquete JSON recibido: {json.dumps({'ID': id, 'Type': Type, 'Payload': Payload, 'PSN': psn}, indent=4)}")  # Mostrar el paquete JSON recibido
                print(f"\nMensaje cifrado recibido: {Payload}")  # Mostrar el mensaje cifrado recibido
                mensaje_texto = procesar_mensaje(Payload, K[num_msj], psn)
                num_msj += 1
                print(f"\nMensaje descifrado: {mensaje_texto}")  # Imprime el mensaje descifrado
                respuesta_server("RM", "Mensaje regular recibido")
            elif Type == "0111":
                K = []
                num_msj = 0  # Reiniciar el contador de mensajes al actualizar las llaves
                P, Q, S, N = Payload
                generador_llaver(P, Q, S, N)
                respuesta_server("KUM", "Actualización de llaves")
conexion.close()

