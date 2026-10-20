FROM python:3.11-slim

WORKDIR /app

# Install decompression libraries for Fastboot (.tgz) and Recovery (.zip / payload.bin)
RUN apt-get update && apt-get install -y \
    curl \
    liblzma-dev \
    libbz2-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# Install verified Python packages
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    huggingface_hub \
    requests \
    remotezip \
    zstandard \
    stream-unzip
# Route Hugging Face staging cache to /tmp so it is wiped after every upload
ENV HF_HOME=/tmp/hf_cache

COPY app.py /app/app.py

EXPOSE 7860
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-7860}"]
