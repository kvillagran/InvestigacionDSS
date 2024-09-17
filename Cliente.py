#----------------------- RECURSOS Y LIBRERIAS -------------------------
import socket
import json
from tabulate import tabulate
import random
import time
from tqdm import tqdm 

#----------------------- VARIABLES -------------------------
K, cod_psn, con, num_msj = [], [], 0, 0
cod_psn = [
    ["1234", "0001"], ["1324", "0010"], ["1423", "0011"], ["2134", "0100"],
    ["2314", "0101"], ["2413", "0110"], ["3124", "0111"], ["3214", "1000"],
    ["3412", "1001"], ["4123", "1010"], ["4213", "1011"], ["4312", "1100"],
    ["4321", "1101"], ["2314", "1110"], ["3421", "1111"]
]

# Generador de ID cliente
numero_aleatorio = random.randint(0, 63)
id_binario = format(numero_aleatorio, '06b')

#----------------------- FUNCIONES GENERALES -------------------------
def barra_de_carga(proceso, iteraciones, retraso=0.1):
    """Barra de progreso utilizando tqdm"""
    for _ in tqdm(range(iteraciones * 5), desc=proceso):
        time.sleep(retraso)

def generar_numero_binario_4_bits():
    return format(random.randint(0, 15), '04b')

def generar_numero_binario_64_bits():
    return ''.join(random.choice('01') for _ in range(64))

def ingresar_valor_entero_positivo(mensaje):
    while True:
        valor = input(mensaje)
        try:
            valor = int(valor)
            if valor > 0:
                return valor
            else:
                print("El valor debe ser un entero positivo mayor que cero.")
        except ValueError:
            print("El valor debe ser un entero positivo mayor que cero.")

def cadena_a_64bit(text):
    binary_text = ''.join(format(ord(char), '08b') for char in text).ljust(64, '0')
    return binary_text[:64]

def convertir_a_json(ID, Type, Payload, PSN):
    return json.dumps({"ID": ID, "Type": Type, "Payload": Payload, "PSN": PSN})

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

#----------------------- FUNCIONES PARA MENSAJE -------------------------
def ejecutar_segun_orden(psn, mensaje, K):
    for numero in psn:
        if numero == '1':
            mensaje = xornot(mensaje, K)
        elif numero == '2':
            mensaje = xor_sust(mensaje, K, int(psn[0]))
        elif numero == '3':
            mensaje = xor_rot(mensaje, K, int(psn[-1]))
        elif numero == '4':
            mensaje = xor_binario(mensaje, K)
    return mensaje

def encontrar_orden(valor_4bits, cod_psn):
    return next((fila[0] for fila in cod_psn if fila[1] == valor_4bits), None)

def procesar_mensaje(mensaje, K, psn):
    mensaje_en_bit = cadena_a_64bit(mensaje)
    barra_de_carga("Cifrando Mensaje", 4)
    return ejecutar_segun_orden(encontrar_orden(psn, cod_psn), mensaje_en_bit, K)

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
    tabular(K)

def fcm():
    P, Q, S, N = obtener_valores()
    generador_llaver(P, Q, S, N)
    return convertir_a_json(id_binario, '0001', [P, Q, S, N], "0")

def obtener_valores():
    return [generar_numero_binario_64_bits() for _ in range(3)] + [ingresar_valor_entero_positivo("Ingrese N: ")]

def mostrar_menu():
    print("\n         SELECCIÓN DE OPCIONES         ")
    print("1. Primer mensaje")
    print("2. Mensaje regular")
    print("3. Actualización de llaves")
    print("4. Último contacto")
    print("="*40)

def obtener_codigo(opcion):
    opciones_validas = [1, 2, 3, 4]
    return opcion if opcion in opciones_validas else 0

#----------------------- CONEXION -------------------------
receptor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receptor.connect(("localhost", 12345))

while True:
    mostrar_menu()
    opcion = int(input("Elija una opción (1-4): "))
    
    if opcion == 5:
        print("Cerrando conexión")
        receptor.send("5".encode())
        break

    codigo = obtener_codigo(opcion)
    if codigo == 1:
        if con == 0:
            K = []
            num_msj = 0  # Reiniciar el contador de mensajes
            mensaje = fcm()
            receptor.send(mensaje.encode())
            print("Mensaje recibido:", receptor.recv(1024).decode())
            con = 1
        else:
            print("Error: La conexión ya fue establecida\n")
    elif con == 1:
        if codigo == 2 and K:
            psn = generar_numero_binario_4_bits()
            texto = input("Ingrese el mensaje que desea enviar: ")
            payload = procesar_mensaje(texto, K[num_msj], psn)
            mensaje = convertir_a_json(id_binario, '0011', payload, psn)
            print(f"\nPaquete JSON a enviar: {json.dumps(json.loads(mensaje), indent=4)}") # Mostrar el paquete JSON completo a enviar
            print(f"\nMensaje cifrado a enviar: {payload}")  # Mostrar el mensaje cifrado
            receptor.send(mensaje.encode())
            print("Mensaje recibido:", receptor.recv(1024).decode())
            num_msj += 1
            if num_msj == len(K):
                K = []
        elif codigo == 3:
            K = []
            num_msj = 0  # Reiniciar el contador de mensajes al actualizar las llaves
            mensaje = fcm()
            receptor.send(mensaje.encode())
            print("Proceso terminado:", receptor.recv(1024).decode())
        elif codigo == 4:
            print("Cerrando conexión")
            receptor.send(convertir_a_json(id_binario, '1111', "", "").encode())
            break
    else:
        print("No se ha establecido conexión/no se han creado llaves\n")
receptor.close()
