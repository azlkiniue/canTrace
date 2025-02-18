#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/version.h>
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

struct data_t
{
  char command[16];
  char devname[30];
  u64 payload[16];
};

BPF_RINGBUF_OUTPUT(events, 1);

int count_packets(struct netif_rx_args *ctx)
{
  struct sk_buff *skb;
  struct net_device *dev;
  struct data_t data = {};
  unsigned char *payload_data;

  skb = (struct sk_buff *)ctx->skbptr;
  dev = _(skb->dev);

  // Get device name
  bpf_probe_read(&data.devname, sizeof(data.devname), dev->name);

  // Filter only CAN devices
  if (data.devname[0] == 'c' && data.devname[1] == 'a' && data.devname[2] == 'n')
  {
    // Get command
    bpf_get_current_comm(&data.command, sizeof(data.command));

    // Read raw data from skb payload
    payload_data = (unsigned char *)_(skb->data); // Explicitly cast to unsigned char *
    bpf_probe_read(&data.payload, sizeof(data.payload), payload_data);

    // Write to ring buffer
    events.ringbuf_output(&data, sizeof(data), 0);
  }

  return 0;
}
