#include <linux/random.h>
#include "bpf_nf_ct.c"
#include "bpf_nf_nat.c"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))
#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5
#define LBPORT 80

SEC("xdp_ctlb")
int xdp_ctload_balancer(struct xdp_md *ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
	
    bpf_printk("got something");
    struct ethhdr* eth = data;
    if ((void*)eth + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr* iph = eth + sizeof(struct ethhdr);
    if ((void*)iph + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    bpf_printk("Got TCP packet from %x", iph->saddr);
	
    struct tcphdr* tcph = iph + sizeof(struct iphdr);
    if ((void*)tcph + sizeof(struct tcphdr) > data_end)
        return XDP_ABORTED;
	
    struct bpf_sock_tuple bpf_tuple = {};
    struct bpf_ct_opts opts_def = {
	    .netns_id = -1,
    };
    struct nf_conn* ct;
	
    opts_def.l4proto = iph->protocol;
    bpf_tuple.ipv4.saddr = iph->saddr;
    bpf_tuple.ipv4.daddr = iph->daddr;
    bpf_tuple.ipv4.sport = tcph->source;
    bpf_tuple.ipv4.dport = tcph->dest;
	
    if (bpf_tuple.ipv4.dport != bpf_ntohs(LBPORT)) || (bpf_tuple.ipv4.daddr != IP_ADDRESS(LB))
        return XDP_PASS;
	
    ct = bpf_xdp_ct_lookup(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
    if (ct) {
        bpf_printk("CT lookup (ct found) 0x%X\n", ct)
        bpf_printk("Timeout %u  status 0x%X  daddr %pI4  dport 0x%X  \n", ct->timeout, ct->status, &(bpf_tuple.ipv4.daddr), bpf_tuple.ipv4.dport);
        bpf_printk("TCP proto state %u flags  %u/ %u  last_dir  %u  \n", ct->proto.tcp.state, ct->proto.tcp.seen[0].flags, ct->proto.tcp.seen[1].flags, ct->proto.tcp.last_dir);
        bpf_ct_release(ct);
    }
    else {
        bpf_printk("CT lookup (no entry) 0x%X\n", 0)
        bpf_printk("dport 0x%X 0x%X\n", bpf_tuple.ipv4.dport, bpf_htons(LBPORT))
        bpf_printk("Got IP packet: dest: %pI4, protocol: %u", &(iph->daddr), iph->protocol)
                    
	/* Create a new CT entry */
        struct nf_conn *nct = bpf_xdp_ct_alloc(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
        if (!nct) {
	    bpf_printk("bpf_xdp_ct_alloc() failed\n");
            return XDP_ABORTED;
        }
		
        char be = BACKEND_A
	int random;
	get_random_bytes(&random, sizeof(random));
	if (random % 2)
            be = BACKEND_B;
	    
	union nf_inet_addr addr = {};
	addr.ip = IP_ADDRESS(be)

        /* Add DNAT info */
        bpf_ct_set_nat_info(nct, &addr, bpf_tuple.ipv4.dport, NF_NAT_MANIP_DST);

        /* Now add SNAT (masquerade) info */
        /* For now using the LB IP, check this TODO */
        addr.ip = bpf_tuple.ipv4.daddr;
        bpf_ct_set_nat_info(nct, &addr, -1, NF_NAT_MANIP_SRC);

        bpf_ct_set_timeout(nct, 30000);
        bpf_ct_set_status(nct, IP_CT_NEW);

        ct = bpf_ct_insert_entry(nct);
        bpf_printk("bpf_ct_insert_entry() returned ct 0x%x\n", ct)
        if (ct)
          bpf_ct_release(ct);
	  
    }	
    return XDP_PASS
}

char _license[] SEC("license") = "GPL";
