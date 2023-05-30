// SPDX-License-Identifier: GPL-2.0-only
/* Unstable Conntrack Helpers for XDP and TC-BPF hook
 *
 * These are called from the XDP and SCHED_CLS BPF programs. Note that it is
 * allowed to break compatibility for these functions since the interface they
 * are exposed through to BPF programs is explicitly unstable.
 */

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/btf_ids.h>
#include <linux/net_namespace.h>
#include <net/netfilter/nf_conntrack_bpf.h>
#include <net/netfilter/nf_conntrack_core.h>

/* bpf_ct_opts - Options for CT lookup helpers
 *
 * Members:
 * @netns_id   - Specify the network namespace for lookup
 *		 Values:
 *		   BPF_F_CURRENT_NETNS (-1)
 *		     Use namespace associated with ctx (xdp_md, __sk_buff)
 *		   [0, S32_MAX]
 *		     Network Namespace ID
 * @error      - Out parameter, set for any errors encountered
 *		 Values:
 *		   -EINVAL - Passed NULL for bpf_tuple pointer
 *		   -EINVAL - opts->reserved is not 0
 *		   -EINVAL - netns_id is less than -1
 *		   -EINVAL - opts__sz isn't NF_BPF_CT_OPTS_SZ (12)
 *		   -EPROTO - l4proto isn't one of IPPROTO_TCP or IPPROTO_UDP
 *		   -ENONET - No network namespace found for netns_id
 *		   -ENOENT - Conntrack lookup could not find entry for tuple
 *		   -EAFNOSUPPORT - tuple__sz isn't one of sizeof(tuple->ipv4)
 *				   or sizeof(tuple->ipv6)
 * @l4proto    - Layer 4 protocol
 *		 Values:
 *		   IPPROTO_TCP, IPPROTO_UDP
 * @dir:       - connection tracking tuple direction.
 * @reserved   - Reserved member, will be reused for more options in future
 *		 Values:
 *		   0
 */
struct bpf_ct_opts {
	s32 netns_id;
	s32 error;
	u8 l4proto;
	u8 dir;
	u8 reserved[2];
};

static int bpf_nf_ct_tuple_parse(struct bpf_sock_tuple *bpf_tuple,
				 u32 tuple_len, u8 protonum, u8 dir,
				 struct nf_conntrack_tuple *tuple);

static struct nf_conn*
__bpf_nf_ct_alloc_entry(struct net *net, struct bpf_sock_tuple *bpf_tuple,
			u32 tuple_len, struct bpf_ct_opts *opts, u32 opts_len,
			u32 timeout);

static struct nf_conn* __bpf_nf_ct_lookup(struct net *net,
					  struct bpf_sock_tuple *bpf_tuple,
					  u32 tuple_len, struct bpf_ct_opts *opts,
					  u32 opts_len);

/* Check writes into `struct nf_conn` */
static int _nf_conntrack_btf_struct_access(struct bpf_verifier_log *log,
					   const struct bpf_reg_state *reg,
					   int off, int size, enum bpf_access_type atype,
					   u32 *next_btf_id, enum bpf_type_flag *flag);

/* bpf_xdp_ct_alloc - Allocate a new CT entry
 *
 * Parameters:
 * @xdp_ctx	- Pointer to ctx (xdp_md) in XDP program
 *		    Cannot be NULL
 * @bpf_tuple	- Pointer to memory representing the tuple to look up
 *		    Cannot be NULL
 * @tuple__sz	- Length of the tuple structure
 *		    Must be one of sizeof(bpf_tuple->ipv4) or
 *		    sizeof(bpf_tuple->ipv6)
 * @opts	- Additional options for allocation (documented above)
 *		    Cannot be NULL
 * @opts__sz	- Length of the bpf_ct_opts structure
 *		    Must be NF_BPF_CT_OPTS_SZ (12)
 */
struct nf_conn *bpf_xdp_ct_alloc(struct xdp_md *, struct bpf_sock_tuple *, u32,
				 struct bpf_ct_opts___local *, u32) __ksym;
				 
/* bpf_xdp_ct_lookup - Lookup CT entry for the given tuple, and acquire a
 *		       reference to it
 *
 * Parameters:
 * @xdp_ctx	- Pointer to ctx (xdp_md) in XDP program
 *		    Cannot be NULL
 * @bpf_tuple	- Pointer to memory representing the tuple to look up
 *		    Cannot be NULL
 * @tuple__sz	- Length of the tuple structure
 *		    Must be one of sizeof(bpf_tuple->ipv4) or
 *		    sizeof(bpf_tuple->ipv6)
 * @opts	- Additional options for lookup (documented above)
 *		    Cannot be NULL
 * @opts__sz	- Length of the bpf_ct_opts structure
 *		    Must be NF_BPF_CT_OPTS_SZ (12)
 */
struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *, struct bpf_sock_tuple *, u32,
				  struct bpf_ct_opts___local *, u32) __ksym;

/* bpf_skb_ct_alloc - Allocate a new CT entry
 *
 * Parameters:
 * @skb_ctx	- Pointer to ctx (__sk_buff) in TC program
 *		    Cannot be NULL
 * @bpf_tuple	- Pointer to memory representing the tuple to look up
 *		    Cannot be NULL
 * @tuple__sz	- Length of the tuple structure
 *		    Must be one of sizeof(bpf_tuple->ipv4) or
 *		    sizeof(bpf_tuple->ipv6)
 * @opts	- Additional options for allocation (documented above)
 *		    Cannot be NULL
 * @opts__sz	- Length of the bpf_ct_opts structure
 *		    Must be NF_BPF_CT_OPTS_SZ (12)
 */ 
struct nf_conn *bpf_skb_ct_alloc(struct __sk_buff *, struct bpf_sock_tuple *, u32,
				 struct bpf_ct_opts___local *, u32) __ksym;

/* bpf_skb_ct_lookup - Lookup CT entry for the given tuple, and acquire a
 *		       reference to it
 *
 * Parameters:
 * @skb_ctx	- Pointer to ctx (__sk_buff) in TC program
 *		    Cannot be NULL
 * @bpf_tuple	- Pointer to memory representing the tuple to look up
 *		    Cannot be NULL
 * @tuple__sz	- Length of the tuple structure
 *		    Must be one of sizeof(bpf_tuple->ipv4) or
 *		    sizeof(bpf_tuple->ipv6)
 * @opts	- Additional options for lookup (documented above)
 *		    Cannot be NULL
 * @opts__sz	- Length of the bpf_ct_opts structure
 *		    Must be NF_BPF_CT_OPTS_SZ (12)
 */ 
struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, u32,
				  struct bpf_ct_opts___local *, u32) __ksym;

/* bpf_ct_insert_entry - Add the provided entry into a CT map
 *
 * This must be invoked for referenced PTR_TO_BTF_ID.
 *
 * @nfct	 - Pointer to referenced nf_conn___init object, obtained
 *		   using bpf_xdp_ct_alloc or bpf_skb_ct_alloc.
 */
struct nf_conn *bpf_ct_insert_entry(struct nf_conn *) __ksym;

/* bpf_ct_release - Release acquired nf_conn object
 *
 * This must be invoked for referenced PTR_TO_BTF_ID, and the verifier rejects
 * the program if any references remain in the program in all of the explored
 * states.
 *
 * Parameters:
 * @nf_conn	 - Pointer to referenced nf_conn object, obtained using
 *		   bpf_xdp_ct_lookup or bpf_skb_ct_lookup.
 */
void bpf_ct_release(struct nf_conn *) __ksym;

/* bpf_ct_set_timeout - Set timeout of allocated nf_conn
 *
 * Sets the default timeout of newly allocated nf_conn before insertion.
 * This helper must be invoked for refcounted pointer to nf_conn___init.
 *
 * Parameters:
 * @nfct	 - Pointer to referenced nf_conn object, obtained using
 *                 bpf_xdp_ct_alloc or bpf_skb_ct_alloc.
 * @timeout      - Timeout in msecs.
 */
void bpf_ct_set_timeout(struct nf_conn *, u32) __ksym;



int bpf_ct_set_nat_info(struct nf_conn *, union nf_inet_addr *,
			int port, enum nf_nat_manip_type___local) __ksym;

/* bpf_ct_change_timeout - Change timeout of inserted nf_conn
 *
 * Change timeout associated of the inserted or looked up nf_conn.
 * This helper must be invoked for refcounted pointer to nf_conn.
 *
 * Parameters:
 * @nfct	 - Pointer to referenced nf_conn object, obtained using
 *		   bpf_ct_insert_entry, bpf_xdp_ct_lookup, or bpf_skb_ct_lookup.
 * @timeout      - New timeout in msecs.
 */
int bpf_ct_change_timeout(struct nf_conn *, u32) __ksym;

/* bpf_ct_set_status - Set status field of allocated nf_conn
 *
 * Set the status field of the newly allocated nf_conn before insertion.
 * This must be invoked for referenced PTR_TO_BTF_ID to nf_conn___init.
 *
 * Parameters:
 * @nfct	 - Pointer to referenced nf_conn object, obtained using
 *		   bpf_xdp_ct_alloc or bpf_skb_ct_alloc.
 * @status       - New status value.
 */
int bpf_ct_set_status(struct nf_conn *, u32) __ksym;

/* bpf_ct_change_status - Change status of inserted nf_conn
 *
 * Change the status field of the provided connection tracking entry.
 * This must be invoked for referenced PTR_TO_BTF_ID to nf_conn.
 *
 * Parameters:
 * @nfct	 - Pointer to referenced nf_conn object, obtained using
 *		   bpf_ct_insert_entry, bpf_xdp_ct_lookup or bpf_skb_ct_lookup.
 * @status       - New status value.
 */
int bpf_ct_change_status(struct nf_conn *, u32) __ksym;

int register_nf_conntrack_bpf(void);

void cleanup_nf_conntrack_bpf(void);
