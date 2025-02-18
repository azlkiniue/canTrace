#!/usr/bin/python3  
from bcc import BPF
import sys, signal

b = BPF(src_file="can_trace_v1.c")
tp = b"net:netif_receive_skb"
b.attach_tracepoint(tp=tp, fn_name="count_packets")

def signal_handler(signal, frame):
    print("")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

b.trace_print()
