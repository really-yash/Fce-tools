FROM python:3.11-slim

WORKDIR /app

# Install ROM Dumper + DNA & Manager filesystem tools (EROFS, EXT4, F2FS, Sparse, 7z, Brotli, Tor)
RUN apt-get update && apt-get install -y \
    curl \
    tor \
    erofs-utils \
    e2fsprogs \
    f2fs-tools \
    android-sdk-libsparse-utils \
    p7zip-full \
    brotli \
    liblzma-dev \
    libbz2-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure Tor SOCKS5 (9050) and ControlPort (9051) for Post-Download IP Rotation
RUN printf "SocksPort 9050\nControlPort 9051\nCookieAuthentication 0\nDataDirectory /tmp/tor_data\n" > /etc/tor/torrc \
    && mkdir -p /tmp/tor_data && chmod 700 /tmp/tor_data

# Install all required Python packages
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    python-multipart \
    huggingface_hub \
    "requests[socks]" \
    PySocks \
    stem \
    brotli \
    remotezip \
    zstandard \
    stream-unzip

ENV HF_HOME=/tmp/hf_cache

COPY app.py /app/app.py
COPY dna_manager.py /app/dna_manager.py

EXPOSE 7860

CMD ["sh", "-c", "tor --RunAsDaemon 1 || true; uvicorn app:app --host 0.0.0.0 --port ${PORT:-7860}"]
