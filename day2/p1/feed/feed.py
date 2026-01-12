from scapy.all import IP, TCP, send, conf, L3RawSocket
import time

FIXED_TARGET_IP = "1.2.3.4"
FIXED_TARGET_PORT = 9999

conf.L3socket = L3RawSocket

def send_custom_tcp_packet(seq_val):
    packet = IP(dst=FIXED_TARGET_IP) / TCP(dport=FIXED_TARGET_PORT, seq=seq_val)
    print(
        f"Sending packet to {FIXED_TARGET_IP}:{FIXED_TARGET_PORT} with Sequence Number: {seq_val}"
    )
    send(packet, verbose=False)


for raw_interval in input().split(","):
    raw_left, raw_right = raw_interval.split("-")
    left, right = int(raw_left), int(raw_right)
    print(f"left = {left}, right = {right}")
    for num in range(left, right + 1):
        send_custom_tcp_packet(num)
        time.sleep(0.001)
