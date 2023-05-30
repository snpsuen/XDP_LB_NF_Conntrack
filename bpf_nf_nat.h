#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum nf_nat_manip_type___local {
	NF_NAT_MANIP_SRC___local,
	NF_NAT_MANIP_DST___local
};

int bpf_ct_set_nat_info(struct nf_conn *, union nf_inet_addr *,
			int port, enum nf_nat_manip_type___local) __ksym;
