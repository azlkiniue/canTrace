#include <uapi/linux/bpf.h>
#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/raw.h>

#define _(P) ({ typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val; })

struct netif_rx_args
{
  long nameptr;
  long skbptr;
  long len;
};

int count_packets(struct netif_rx_args *ctx)
{
  struct sk_buff *skb;
  struct net_device *dev;
  char devname[30] = {0};
  unsigned char *data; 
  unsigned char raw_data[16] = {0}; // Buffer for raw CAN data
  unsigned char command[16] = {0};

  skb = (struct sk_buff *)ctx->skbptr;
  dev = _(skb->dev);

  // Get device name
  bpf_probe_read(devname, sizeof(devname), dev->name);

  // Filter only CAN devices
  if (devname[0] == 'c' && devname[1] == 'a' && devname[2] == 'n')
  {
    bpf_trace_printk("devname: %s", devname);

    // Read raw data from skb payload
    data = (unsigned char *)_(skb->data); // Explicitly cast to unsigned char *
    bpf_probe_read(raw_data, sizeof(raw_data), data);

    // Get command
    bpf_get_current_comm(command, sizeof(command));
    bpf_trace_printk("command: %s", command);

    // // print raw data
    // for (int i = 8; i < 16; i++)
    // {
    //     bpf_trace_printk("raw_data[%d]: 0x%x", i, raw_data[i]);
    // }

    // subtract 80 hex from the fourth byte of 
    // the raw data if it is greater than 80 hex
    if (raw_data[3] > 0x80)
      raw_data[3] -= 0x80;

    bpf_trace_printk("can_id: %x %x", raw_data[3], raw_data[2]);
    bpf_trace_printk("can_id: %x %x", raw_data[1], raw_data[0]);

    bpf_trace_printk("payload: %x %x", raw_data[8], raw_data[9]);
    bpf_trace_printk("payload: %x %x", raw_data[10], raw_data[11]);
    bpf_trace_printk("payload: %x %x", raw_data[12], raw_data[13]);
    bpf_trace_printk("payload: %x %x", raw_data[14], raw_data[15]);
  }

  return 0;
}