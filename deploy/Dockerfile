FROM python:3.12-slim

WORKDIR /app

# deps first for layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY oobox ./oobox
RUN pip install --no-cache-dir .

# Runtime state (DB + hosted payloads) lives here; mount a volume.
ENV OOB_DB=/data/oobox.db \
    OOB_FILES_DIR=/data/hosted
VOLUME ["/data", "/certs"]

# DNS(53) HTTP(80) HTTPS(443) SMTP(25) control-API(8443)
EXPOSE 53/udp 53/tcp 80 443 25 8443

ENTRYPOINT ["python", "-m", "oobox"]
CMD ["serve"]
