FROM python:3.12-slim
RUN pip install --no-cache-dir "cryptography>=42" \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin collector \
 && install -d -m 700 -o collector -g collector /data
COPY --chmod=644 guardian_collector.py /app/guardian_collector.py
ENV GUARDIAN_COLLECTOR_DATA=/data PYTHONDONTWRITEBYTECODE=1
USER collector
VOLUME /data
ENTRYPOINT ["python", "/app/guardian_collector.py"]
CMD ["status"]
