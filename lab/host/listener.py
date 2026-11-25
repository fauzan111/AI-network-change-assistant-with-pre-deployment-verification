"""Accept TCP connections on the given ports and answer '<hostname>:<port>'.

usage: listener.py 22 80 443
"""
import socket
import sys
import threading

HOST = socket.gethostname()


def serve(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        try:
            conn.sendall(f"{HOST}:{port}\n".encode())
        finally:
            conn.close()


if __name__ == "__main__":
    ports = [int(p) for p in sys.argv[1:]]
    for p in ports:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    threading.Event().wait()
