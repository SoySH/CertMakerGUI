## 🖥 Compilación desde código fuente

### Ubuntu

1. Instalar dependencias del sistema:

sudo apt update
sudo apt install libxcb-xinerama0 libxkbcommon-x11-0 libxcb1 libx11-xcb1 libxcb-util1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-shm0 libxcb-sync1 libxcb-xfixes0 libxcb-xkb1

2. Crear carpeta del proyecto y entrar: 
mkdir cert-maker-gui && cd cert-maker-gui

3. Crear y activar entorno virtual:

python -m venv .venv
source .venv/bin/activate


4. Instalar dependencias:

pip install PyQt5 cryptography pyinstaller


5. Empaquetar en ejecutable:

pyinstaller --onefile --noconsole --name CertMakerGUI app.py

6. El ejecutable se genera en dist/.

NOTA: Si no abre con doble clic, dar permiso de ejecución:

chmod +x dist/CertMakerGUI
