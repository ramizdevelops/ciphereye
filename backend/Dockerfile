FROM python:3.11-slim

# System dependencies for forensics tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    file \
    foremost \
    exiftool \
    strings \
    xxd \
    steghide \
    stegosuite \
    libmagic1 \
    libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Sherlock for username OSINT
RUN pip install --no-cache-dir sherlock-project

COPY . .

RUN mkdir -p /app/uploads

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
