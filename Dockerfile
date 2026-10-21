FROM python:3.11-slim

WORKDIR /app

# Install decompression libraries + Tor daemon for Post-Download IP Rotation
RUN apt-get update && apt-get install -y \
    curl \
    tor \
    liblzma-dev \
    libbz2-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure Tor SOCKS5 (9050) and ControlPort (9051) for stem Signal.NEWNYM rotation
RUN printf "SocksPort 9050\nControlPort 9051\nCookieAuthentication 0\nDataDirectory /tmp/tor_data\n" > /etc/tor/torrc \
    && mkdir -p /tmp/tor_data && chmod 700 /tmp/tor_data

# Install all required Python packages (including SOCKS5 proxy & stem controller support)
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    huggingface_hub \
    "requests[socks]" \
    PySocks \
    stem \
    remotezip \
    zstandard \
    stream-unzip

# Route Hugging Face staging cache to /tmp so it is wiped after every upload
ENV HF_HOME=/tmp/hf_cache

COPY app.py /app/app.py

EXPOSE 7860

# Start Tor in the background for IP rotation, then launch the FastAPI server
CMD ["sh", "-c", "tor --RunAsDaemon 1 || true; uvicorn app:app --host 0.0.0.0 --port ${PORT:-7860}"]
