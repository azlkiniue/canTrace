#!/usr/bin/python3  
from bcc import BPF

b = BPF(src_file="can_trace_v1.c")
tp = b"net:netif_receive_skb"
b.attach_tracepoint(tp=tp, fn_name="count_packets")

b.trace_print()
