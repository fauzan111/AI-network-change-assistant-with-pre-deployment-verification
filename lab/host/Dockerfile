# Lab end host: iptables host firewall, netcat for probes, a tiny multi-port TCP listener.
FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 netcat-openbsd python3 tcpdump curl
COPY listener.py /usr/local/bin/listener.py
CMD ["sleep", "infinity"]
