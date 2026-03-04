[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/SoySH/CertMakerGUI)

## 🖥 Compilación desde código fuente

### Ubuntu 22.04.5

1. Instalar dependencias del sistema:

sudo apt update
sudo apt update && sudo apt install -y \
    python3-venv python3-pip \
    libxcb-xinerama0 libxkbcommon-x11-0 libxcb1 libx11-xcb1 \
    libxcb-util1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
    libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-shm0 \
    libxcb-sync1 libxcb-xfixes0 libxcb-xkb1

2. Crear carpeta como usuario normal y acceder al proyecto:

mkdir cert-maker-gui && cd cert-maker-gui

3. Crear y activar entorno virtual:

python -m venv .venv

source .venv/bin/activate


4. Instalar dependencias:

pip install PyQt5 cryptography pyinstaller


5. Empaquetar en ejecutable:

pyinstaller --onefile --noconsole --name CertMakerGUI app.py

6. El ejecutable se genera en dist/.

---

# CertMaker LINUX

**Cert-Maker** es una herramienta multiplataforma (Windows y Ubuntu) para generar certificados TLS autofirmados de manera rápida y sencilla.  
Es totalmente portable, no requiere Python instalado y ofrece una interfaz gráfica intuitiva basada en **PyQt5**.

## Requisito minimo de sistema:
 🔹Ubuntu 22.04.5

## Características

- **Generación de CA** y certificados de servidor.
- Soporte para **SANs** (Subject Alternative Names).
- Duración del certificado del servidor en días.
- **Modo rápido**: utiliza valores predeterminados para generar certificados en segundos.
- **Modo manual**: permite especificar campos como `CN`, `O`, `OU`, `C`, `ST`, `L`, `NS`.
- Exporta en múltiples formatos: `.key`, `.crt`, `.pem`, `.cer`, `.csr`, `.pfx`.
- Ejecutable listo para **Ubuntu**.

## Tecnologías utilizadas

- **Python 3.10**
- **PyQt5** – Interfaz gráfica
- **cryptography** – Generación de certificados
- **PyInstaller** – Empaquetado de ejecutables

- **NOTA**: Si no abre con doble clic, dar permiso de ejecución:

chmod +x dist/CertMakerGUI

<img width="1240" height="976" alt="Captura desde 2026-03-04 01-43-16" src="https://github.com/user-attachments/assets/1bc43183-fb9f-4353-8164-2e87201e67f2" />



