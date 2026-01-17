from scapy.all import IP, TCP, send, conf, L3RawSocket

FIXED_TARGET_PORT = 9999

conf.L3socket = L3RawSocket


def send_custom_tcp_packet(input_num):
    target_ip = (
        str((input_num % 2**32) // 2**24)
        + "."
        + str((input_num % 2**24) // 2**16)
        + "."
        + str((input_num % 2**16) // 2**8)
        + "."
        + str(input_num % (2**8))
    )
    seq_val = input_num // 2**32
    packet = IP(dst=target_ip) / TCP(dport=FIXED_TARGET_PORT, seq=seq_val)
    print(
        f"Sending packet to {target_ip}:{FIXED_TARGET_PORT} with Sequence Number: {seq_val} representing {input_num}"
    )
    send(packet, verbose=False)


num_intervals = 0
for raw_interval in input().split(","):
    raw_left, raw_right = raw_interval.split("-")
    left, right = int(raw_left), int(raw_right)
    for num in range(left, right + 1):
        send_custom_tcp_packet(num)
