

import os # Librería para interactuar con el SO. (borrar terminal o gestionar archivos)- 
import sys # Librería para controlar el propio entorno de Python (cerrar el programa limpiamente).
import hashlib  # Librería criptográfica para generar huellas digitales (Hashes)

def limpiar_pantalla():
    """
    Función auxiliar para limpiar la terminal y que el menú 
    se vea ordenado cada vez que el usuario elige una opción.
    """
    os.system('clear')

def modulo_preventivo():
    """
    Módulo Preventivo: Analiza la seguridad de la autenticación en el Host.    
    """
    limpiar_pantalla()
    print("==================================================")
    print("    MÓDULO PREVENTIVO: SEGURIDAD EN EL HOST       ")
    print("==================================================")
    print("[*] Analizando las cuentas de usuario en el sistema...\n")

    # Ruta del archivo del sistema que contiene los usuarios en Linux
    ruta_usuarios = "/etc/passwd"

    # Verificamos primero si el archivo existe (Medida de control de errores con la librería 'os')
    if os.path.exists(ruta_usuarios):
        try:
            # Abrimos el archivo en modo lectura ('r')
            with open(ruta_usuarios, "r") as archivo:
                lineas = archivo.readlines()
                
                print("[+] Usuarios con acceso a consola interactiva encontrados:")
                print("--------------------------------------------------")
                
                # Recorremos cada línea del archivo de configuración de Linux
                for linea in lineas:
                    # En /etc/passwd los datos de los usuarios se separan por dos puntos (:)
                    datos = linea.split(":")
                    nombre_usuario = datos[0]  # El primer elemento es el nombre de usuario
                    consola = datos[-1].strip() # El último elemento es la consola que utiliza
                    
                    # Filtramos: Nos interesan los usuarios reales que pueden iniciar sesión (/bin/bash o /bin/sh)
                    # Evitamos los usuarios del sistema que están deshabilitados (/bin/false o /usr/sbin/nologin)
                    if "bash" in consola or "sh" in consola:
                        print(f" -> Usuario: {nombre_usuario:<15} | Consola: {consola}")
                        
            print("--------------------------------------------------")
            print("Auditoría completada con éxito.")
            print("Minimizar el uso de cuentas compartidas y auditar el grupo sudo.")
            
        except Exception as e:
            # Si ocurre algún error de permisos al leer el archivo, lo capturamos aquí
            print(f"Error al leer el archivo de usuarios: {e}")
    else:
        print("Error crítico: No se encuentra el archivo de configuración del Host.")

    # Pausamos el programa para que puedas leer los resultados antes de volver al menú
    input("\nPresiona Intro para volver al menú principal...")

def modulo_reactivo():
    """
    Módulo Reactivo: Simula la respuesta ante incidentes usando el Firewall del software.    
    """
    limpiar_pantalla()
    print("==================================================")
    print("    MÓDULO REACTIVO: FIREWALL DE SOFTWARE         ")
    print("==================================================")
    print("ALERTA: Se ha detectado tráfico sospechoso.")
    
    # Solicitamos al usuario (el administrador) la IP que quiere bloquear
    ip_bloquear = input("\nIntroduce la IP atacante que deseas bloquear (ej: 192.168.1.50): ").strip()

    # Comprobamos que el usuario no haya dejado el campo vacío
    if not ip_bloquear:
        print("Error: No has introducido ninguna dirección IP.")
    else:
        print(f"\nAplicando enfoque reactivo para contener la amenaza...")
        print("--------------------------------------------------")
        
        # Guardamos en variables los comandos reales de Linux (iptables y ufw)
        # Explicación de las flags de iptables:
        # -A INPUT: Añadir regla al tráfico de entrada
        # -s: Origen (source) de la IP atacante
        # -j DROP: Acción de bloquear/tirar los paquetes sin responder
        comando_iptables = f"sudo iptables -A INPUT -s {ip_bloquear} -j DROP"
        comando_ufw = f"sudo ufw deny from {ip_bloquear}"
        
        print(f"Regla generada con éxito para la IP: {ip_bloquear}")
        print("--------------------------------------------------")
        print("Comandos técnicos que se ejecutarían en el Host:")
        print(f"    -> Opción Estándar (iptables): {comando_iptables}")
        print(f"    -> Opción Simplificada (ufw):  {comando_ufw}")
        print("--------------------------------------------------")
        print("Bloqueo inmediato de capa de red (Capa 3 del modelo OSI).")
        print("Estado: Amenaza mitigada reactivamente. Tráfico cortado.")

    # Pausamos el programa para poder leer los comandos generados
    input("\nPresiona Intro para volver al menú principal...")

def modulo_monitoreo():
    """
    Módulo de Monitoreo: Ejecuta un análisis en tiempo real de las conexiones de red del Host.    
    """
    limpiar_pantalla()
    print("==================================================")
    print("    MÓDULO DE MONITOREO: CONEXIONES DE RED        ")
    print("==================================================")
    print("Lanzando auditoría de red en tiempo real...\n")
    print("Puertos abiertos y conexiones activas encontradas:")
    print("------------------------------------------------------------------")
    print(f"{'PROTOCOLO':<10} | {'ESTADO':<12} | {'DIRECCIÓN LOCAL (Puerto)':<25}")
    print("------------------------------------------------------------------")

    # Comando nativo de Linux para listar sockets/conexiones de red:
    # ss (Socket Statistics) con las flags:
    # -t (tráfico TCP), -u (tráfico UDP), -a (todas las conexiones, escuchando y establecidas)
    comando_ss = "ss -tua"

    try:
        # Usamos os.popen() en lugar de os.system() porque popen() nos permite
        # "capturar" lo que la terminal responde y procesarlo línea a línea en Python.
        resultado_terminal = os.popen(comando_ss).read()
        
        # Partimos la respuesta de la terminal por líneas
        lineas = resultado_terminal.split("\n")
        
        # Nos saltamos la primera línea porque es la cabecera original de 'ss'
        for linea in lineas[1:]:
            # Limpiamos los espacios extras de la línea
            partes = linea.split()
            
            # Si la línea tiene datos válidos (al menos 5 columnas)
            if len(partes) >= 5:
                protocolo = partes[0]   # Ej: tcp, udp
                estado = partes[1]      # Ej: LISTEN (escuchando), ESTAB (conectado)
                dir_local = partes[4]   # Ej: 127.0.0.1:5432 o *:ssh
                
                # Formateamos la salida
                print(f"{protocolo:<10} | {estado:<12} | {dir_local:<25}")
                
        print("------------------------------------------------------------------")
        print("Monitoreo finalizado.")
        print("[Análisis Defensivo]: Busca estados 'LISTEN' en puertos desconocidos.")
        
    except Exception as e:
        print(f"Error al intentar monitorizar la red: {e}")

    # Pausamos el programa
    input("\nPresiona Intro para volver al menú principal...")      

def modulo_retrospectivo():
    """
    Módulo Retrospectivo: Asegura la evidencia digital mediante hashing criptográfico.    
    """
    limpiar_pantalla()
    print("==================================================")
    print("    MÓDULO RETROSPECTIVO: EVIDENCIA DIGITAL        ")
    print("==================================================")
    print("Iniciando fase de recolección de evidencias (Post-Incidente)...\n")
    
    # Simulamos el análisis del archivo de log más importante de autenticación en Linux
    archivo_evidencia = "/var/log/auth.log"
    print(f"Archivo crítico localizado: {archivo_evidencia}")
    print("Calculando huella digital criptográfica para asegurar la Cadena de Custodia...")
    print("------------------------------------------------------------------")

    try:
        #Inicializamos el algoritmo SHA-256 de la librería hashlib
        hash_sha256 = hashlib.sha256()
        
        # Simulamos que leemos el contenido del archivo de logs para generar su hash.
        # En un entorno real leeríamos el archivo físico en modo binario ('rb').
        # Para nuestro laboratorio seguro, usamos un texto que simula el contenido del log:
        contenido_simulado = b"2026-06-01 10:15:23 - User kali login successful\n2026-06-01 11:00:12 - Invalid user admin from 192.168.1.105"
        
        # Pasamos el contenido al algoritmo para que calcule la matemática del hash
        hash_sha256.update(contenido_simulado)
        
        # Extraemos el hash en un formato legible (hexadecimal)
        resultado_hash = hash_sha256.hexdigest()
        
        print(f"[CÓDIGO HASH SHA-256 OBTENIDO]:\n{resultado_hash}")
        print("------------------------------------------------------------------")
        print("[Análisis Forense]: Registro congelado en la bitácora de evidencias.")
        print("Integridad Garantizada: Si el atacante altera este log, el Hash cambiará.")
        
    except Exception as e:
        print(f"Error al procesar la evidencia digital: {e}")

    # Pausamos el programa
    input("\nPresiona Intro para volver al menú principal...")    

def mostrar_menu():
    """
    Muestra en la terminal las opciones del panel SecOps-Shield.
    Cada opción representa una capa de la Defensa en Profundidad.
    """
    limpiar_pantalla()
    print("==================================================")
    print("          SECOPS-SHIELD: PANEL DE DEFENSA         ")
    print("==================================================")
    print(" [1] Enfoque Preventivo: Seguridad en el Host")
    print(" [2] Enfoque Reactivo: Firewall de Software")
    print(" [3] Enfoque de Monitoreo: Conexiones de Red")
    print(" [4] Enfoque Retrospectivo: Evidencia Digital")
    print(" [5] Salir del programa")
    print("==================================================")

def ejecutar_opcion(opcion):
    """
    Gestiona la lógica de la opción seleccionada por el usuario.    
    """
    if opcion == "1":
        modulo_preventivo()
        
        
    elif opcion == "2":
        modulo_reactivo()
        
    elif opcion == "3":
        modulo_monitoreo()
        
    elif opcion == "4":
        modulo_retrospectivo()
        
    elif opcion == "5":
        print("\n[+] Saliendo de SecOps-Shield. ¡Sistema securizado!")
        sys.exit(0)
        
    else:
        print("\nOpción no válida. Por favor, selecciona del 1 al 5.")
        input("\nPresiona Intro para continuar...")

def main():
    """
    Función principal que arranca el programa y mantiene el menú
    activo en un bucle infinito hasta que se decida salir.
    """
    while True:
        mostrar_menu()
        # Solicitamos la opción al usuario en la terminal
        seleccion = input("Elige una capa de defensa (1-5): ")
        ejecutar_opcion(seleccion)

# Este condicional asegura que el código solo se ejecute si lanzamos este archivo directamente
if __name__ == "__main__":
    main()