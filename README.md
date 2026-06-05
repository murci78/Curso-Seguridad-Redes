# Curso de Seguridad en Redes y SecOps

Este repositorio está dedicado a recopilar los proyectos, scripts y herramientas desarrollados durante mi formación avanzada en **Ciberseguridad, Hardening y SecOps**. El objetivo principal es documentar soluciones prácticas de defensa en profundidad, monitorización de sistemas y automatización de seguridad en entornos Linux (Kali Linux).

---

##  Proyecto Destacado: SecOps-Shield

**SecOps-Shield** (`shield.py`) es un script interactivo desarrollado en **Python** diseñado para la gestión táctica de la seguridad de un Host. Actúa como un panel de control centralizado para administradores de sistemas y analistas de seguridad que buscan automatizar la auditoría y el endurecimiento (hardening) de sus entornos.

###  Características Principales

*   **Gestión del Firewall:** Automatización de reglas defensivas mediante la manipulación e inspección de servicios de red.
*   **Monitorización de Host:** Supervisión activa de procesos del sistema y conexiones sospechosas.
*   **Logs y Alertas:** Generación de auditorías para trazar eventos críticos de seguridad en tiempo real.
*   **Interfaz Interactiva:** Menú guiado por consola optimizado para operadores de seguridad en entornos Bash.

###  Requisitos e Instalación

Para ejecutar las herramientas de este repositorio, asegúrate de contar con Python 3 instalado en tu distribución de Linux:

```bash
# Clonar el repositorio
git clone [https://github.com/murci78/Curso-Seguridad-Redes.git](https://github.com/murci78/Curso-Seguridad-Redes.git)

# Acceder al directorio
cd Curso-Seguridad-Redes

# Ejecutar el script principal (Requiere privilegios de administrador para interactuar con el sistema)
sudo python3 shield.py
