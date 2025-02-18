#!/usr/bin/python3  
from bcc import BPF
import sys, signal

b = BPF(src_file="can_trace_v2.c")
tp = b"net:netif_receive_skb"
b.attach_tracepoint(tp=tp, fn_name="count_packets")

def signal_handler(signal, frame):
    print("")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def process_raw_data_field(raw_data_field):
  # Remove leading zeros but ensure at least one zero remains if needed
  hex_string = raw_data_field.lstrip('0')
  if len(hex_string) % 2 != 0:
    hex_string = '0' + hex_string  # Add a leading zero if the length is odd

  # Split into byte chunks (each byte is 2 hex characters)
  bytes_list = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]

  # Reverse the bytes to change endianness
  bytes_list.reverse()

  # Join the bytes with spaces
  return " ".join(bytes_list)

def print_event(cpu, data, size):
  data = b["events"].event(data)
  raw_control_field = f"{data.payload[0]:09x}"
  raw_data_field = f"{data.payload[1]:016x}"
  
  # get the first char of the control field as dlc variable
  dlc = int(raw_control_field[0], 16)
  # get can id from the control field in hex format, strip leading zeros
  can_id = raw_control_field[1:].lstrip('0')
  # if the can id is less than 3 characters, pad with zeros
  if len(can_id) < 3:
    can_id = f"{can_id:0>3}"

  processed_data = process_raw_data_field(raw_data_field)

  print(f"{data.devname.decode()} {data.command.decode():<8} {can_id:>8} [{dlc}] {processed_data}")
 
b["events"].open_ring_buffer(print_event) 
while True:
  b.ring_buffer_poll()