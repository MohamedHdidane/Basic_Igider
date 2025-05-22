FROM itsafeaturemythic/mythic_python_base:latest


RUN apt-get update && apt-get install -y wine64 && rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir pyinstaller cryptography pycryptodome

WORKDIR /Mythic/

CMD ["python3", "main.py"]