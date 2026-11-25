# FRR router for the lab: OSPF + static routing enabled, frr-reload.py available.
FROM quay.io/frrouting/frr:10.2.1
RUN sed -i 's/^ospfd=no/ospfd=yes/; s/^staticd=no/staticd=yes/' /etc/frr/daemons \
 && printf 'service integrated-vtysh-config\n' > /etc/frr/vtysh.conf \
 && printf 'frr defaults traditional\nservice integrated-vtysh-config\n!\n' > /etc/frr/frr.conf \
 && chown -R frr:frr /etc/frr
