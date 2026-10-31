# Build from the repository root:  docker build -f collector/Dockerfile -t guardian-collector:1.1.0 .
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap openssh-client && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "cryptography>=42" "ldap3>=2.9" "pywinrm>=0.4.3" \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin collector \
 && install -d -m 700 -o collector -g collector /data
COPY --chmod=644 collector/guardian_collector.py collector/launch.py /app/
COPY --chmod=644 guardian/__init__.py guardian/jobs.py guardian/access.py guardian/connectors.py guardian/codescan.py guardian/release.py /app/guardian/
ENV GUARDIAN_COLLECTOR_DATA=/data PYTHONDONTWRITEBYTECODE=1
USER collector
VOLUME /data
ENTRYPOINT ["python", "/app/launch.py"]
CMD ["status"]
