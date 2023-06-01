#include "xdp_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

struct five_tuple {
  __u8  protocol;
  __u32 ip_source;
  __u32 ip_destination;
  __u16 port_source;
	__u16 port_destination;
};

struct bpf_map_def SEC("maps") return_traffic = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__16),
	.value_size  = sizeof(__u32),
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") forward_flow = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct five_tuple),
	.value_size  = sizeof(__u32),
	.max_entries = 100000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

SEC("xdp_state_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("got something");

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    bpf_printk("Got TCP packet from %x", iph->saddr);

    if (iph->saddr == IP_ADDRESS(CLIENT))
    {
        char be = BACKEND_A;
        if (bpf_ktime_get_ns() % 2)
            be = BACKEND_B;

        iph->daddr = IP_ADDRESS(be);
        eth->h_dest[5] = be;
    }
    else
    {
        iph->daddr = IP_ADDRESS(CLIENT);
        eth->h_dest[5] = CLIENT;
    }
    iph->saddr = IP_ADDRESS(LB);
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
