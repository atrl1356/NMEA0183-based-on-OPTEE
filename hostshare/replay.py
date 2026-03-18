import socket, time, sys

HOST="127.0.0.1"; PORT=10110
path=sys.argv[1]

sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with open(path, "r", errors="ignore") as f:
    for line in f:
        line=line.strip()
        if not line: 
            continue
        sock.sendto((line+"\r\n").encode("ascii","ignore"), (HOST,PORT))
        time.sleep(0.05)  # 控制速度
