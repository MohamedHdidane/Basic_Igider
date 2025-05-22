FROM itsafeaturemythic/mythic_python_base:latest

# Install system dependencies for PyInstaller and EXE generation
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    zlib1g-dev \
    upx-ucl \
    binutils \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for EXE generation
RUN pip install --no-cache-dir \
    pyinstaller \
    pefile

WORKDIR /Mythic/

CMD ["python3", "main.py"]