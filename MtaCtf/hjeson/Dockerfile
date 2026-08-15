FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y socat supervisor && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf

WORKDIR /home/ctf

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN chown -R ctf:ctf /home/ctf
RUN mkdir -p /var/log/ctf_server && chmod 755 /var/log/ctf_server

EXPOSE 5555

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python3 /home/ctf/src/healthcheck.py

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]