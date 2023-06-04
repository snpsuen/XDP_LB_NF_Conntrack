#include "xdp_state_lb_kern.h"

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
    .key_size    = sizeof(__u16),
    .value_size  = sizeof(__u32),
    .max_entries = 100000,
    .map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") forward_flow = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct five_tuple),
    .value_size  = sizeof(__u8),
    .max_entries = 100000,
    .map_flags   = BPF_F_NO_PREALLOC,
};

SEC("xdp_state_lb")
int xdp_state_load_balancer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct five_tuple forward_key = {};
    __u16 return_key;
    __u32* return_addr;
    __u8 backend;

    bpf_printk("got something");
    struct ethhdr* eth = data;
    if ((void*)eth + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr* iph = (void*)eth + sizeof(struct ethhdr);
    if ((void*)iph + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr* tcph = (void*)iph + sizeof(struct iphdr);
    if ((void*)tcph + sizeof(struct tcphdr) > data_end)
        return XDP_ABORTED;

    bpf_printk("Got TCP packet from %x", iph->saddr);
    if ((iph->saddr == IP_ADDRESS(BACKEND_A)) || (iph->saddr == IP_ADDRESS(BACKEND_B))) {
        
        bpf_printk("Packet returning from the backend %x", iph->saddr);
        return_key = bpf_ntohs(tcph->dest);
        return_addr = bpf_map_lookup_elem(&return_traffic, &return_key);
        if (return_addr == NULL) {
            bpf_printk("Cannot locate a return path for the destination port %hu", return_key);
            return XDP_ABORTED;
        }
        
        bpf_printk("Located client %x from an existing entry in the return traffic table", *return_addr);
        iph->daddr = *return_addr;
        iph->saddr = IP_ADDRESS(LB);
        iph->check = iph_csum(iph);
        return XDP_PASS;
    }
    else {
        bpf_printk("Packet sent from the client %x", iph->saddr);
        forward_key.protocol = iph->protocol;
        forward_key.ip_source = iph->saddr;
        forward_key.ip_destination = iph->daddr;
        forward_key.port_source = bpf_ntohs(tcph->source);
        forward_key.port_destination = bpf_ntohs(tcph->dest);
            
        __u8* forward_backend = bpf_map_lookup_elem(&forward_flow, &forward_key);
        if (forward_backend == NULL) {
            backend = BACKEND_A;
            if (bpf_get_prandom_u32() % 2)
                backend = BACKEND_B;
            
            bpf_printk("Add a new entry to the forward flow table for backend %x", IP_ADDRESS(backend));
            bpf_map_update_elem(&forward_flow, &forward_key, &backend, BPF_ANY);

            __u8 srcport = forward_key.port_source;
            __u32 srcaddr = forward_key.ip_source;
            bpf_printk("Add a new entry to the return traffic table to map client port %x to client address %x", srcport, srcaddr);
            bpf_map_update_elem(&return_traffic, &srcport, &srcaddr, BPF_ANY);      
        }
        else {
            bpf_printk("Located backend %x from an existing entry in the forward flow table ", IP_ADDRESS(*forward_backend));
            backend = *forward_backend;
        }
        
        bpf_printk("Packet to be forwrded to backend %x", IP_ADDRESS(backend));
        iph->daddr = IP_ADDRESS(backend);
        iph->saddr = IP_ADDRESS(LB);
        iph->check = iph_csum(iph);

        eth->h_dest[5] = backend;
        return XDP_TX;
    }
}

char _license[] SEC("license") = "GPL";
