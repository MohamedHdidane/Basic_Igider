FROM itsafeaturemythic/mythic_python_base:latest

#Install dependencies for Wine and PyInstaller

RUN apt-get update \ 
    apt-get install -y wine64 winetricks \ 
    rm -rf /var/lib/apt/lists/*

#Configure Wine for PyInstaller

RUN winetricks -q vcrun2019 \
    winecfg

#Install Python dependencies

RUN pip install --no-cache-dir pyinstaller cryptography pycryptodome wmi

WORKDIR /Mythic/

CMD ["python3", "main.py"]