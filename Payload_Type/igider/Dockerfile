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
    wine \
    wine32 \
    wine64 \
    && rm -rf /var/lib/apt/lists/*

# Configure Wine for cross-compilation (optional for Windows EXE generation on Linux)
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y wine32

# Install Python packages for EXE generation
RUN pip install --no-cache-dir \
    pyinstaller \
    auto-py-to-exe \
    pefile \
    pywin32-ctypes

# Set Wine environment variables
ENV WINEARCH=win64
ENV WINEPREFIX=/root/.wine

# Initialize Wine (suppress output)
RUN wine wineboot --init > /dev/null 2>&1 || true

WORKDIR /Mythic/

CMD ["python3", "main.py"]