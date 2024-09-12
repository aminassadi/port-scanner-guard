#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef ETH_P_PPP_MP
#define ETH_P_PPP_MP 0x0008
#endif /* Dummy type for PPP MP frames */

#define MAX_HALF_OPEN_SOCKET 1024 * 1024
#define HALF_OPEN_SOCKET_LIMIT 10

struct tracepoint__sock__inet_sock_set_state
{
	uint64_t pad;
	const void *skaddr; // kernel struct sock *
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_HALF_OPEN_SOCKET);
	__type(key, __be32);
	__type(value, int);
} half_open_socket_map SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 100 * 1024);
} perf_buff SEC(".maps");

typedef enum
{
	FAMILY_AF_INET = 2,
	FAMILY_AF_INET6 = 10
} family;

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	//return XDP_PASS;
	int pkt_len = 0, map_index;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	uint32_t size = data_end - data;
	if (size != 60) //syn packet size
	 	return XDP_PASS;
	//bpf_printk("size = %d\n", size);
	struct ethhdr *eth = data;
	//
	// data plane 
	//

	// int ret = bpf_perf_event_output(ctx, &perf_buff, BPF_F_CURRENT_CPU, data, size);  //write to perf buff
    // if (ret != 0)
    // {
    //     bpf_printk("ERROR, output to perf buffer, code:%ld", ret);
    // }

	struct iphdr *ip;
	long *value;
	struct ipv6hdr h;
	pkt_len = sizeof(*eth);
	ip = data + pkt_len;
	pkt_len += sizeof(struct iphdr);
	if (data + pkt_len > data_end)
		return XDP_DROP;
	// map_index = ip->protocol;
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
		bpf_printk("rcv packet protocol ipv4\n");
	else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6)
		bpf_printk("rcv packet protocol ipv6\n");
	else if (bpf_ntohs(eth->h_proto) == ETH_P_ARP)
	{
		// bpf_printk("rcv packet protocol ARP\n");
		return XDP_PASS;
	}
	else if ((bpf_ntohs(eth->h_proto) == ETH_P_PPP_MP))
	{
		bpf_printk("rcv packet protocol MULTI FRAME PROTOCOL\n");
	}
	else
	{
		bpf_printk("rcv packet protocol id:%d\n", bpf_ntohs(eth->h_proto));
	}
	if(bpf_ntohl(ip->daddr) != 0xc0a8e783)
		return XDP_PASS;
	if (ip->protocol == IPPROTO_ICMP)
	{
		bpf_printk("rcv packet at queue %u, ip = %x\n", ctx->rx_queue_index, bpf_ntohl(ip->daddr));
	}
	else if (ip->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcp = data + pkt_len;
		pkt_len += sizeof(struct tcphdr);
		if (data + pkt_len > data_end)
			return XDP_DROP;
		bpf_printk("rcv tcp packet at queue %u, ip= %x, dport= %d, sport= %d\n", ctx->rx_queue_index, bpf_ntohl(ip->daddr), bpf_ntohs(tcp->dest), tcp->source);
	}
	else if (ip->protocol == IPPROTO_UDP)
	{
		struct udphdr *udp = data + pkt_len;
		pkt_len += sizeof(struct udphdr);
		if (data + pkt_len > data_end)
			return XDP_DROP;
		bpf_printk("rcv packet at queue %u, ip = %x\n", ctx->rx_queue_index, bpf_ntohl(ip->daddr));
	}
	return XDP_PASS;
}

SEC("tracepoint/sock/inet_sock_set_state")
__attribute__((flatten)) int TCPconnection(struct tracepoint__sock__inet_sock_set_state *args)
{
	// if (args->oldstate == TCP_LISTEN && args->newstate == TCP_SYN_RECV)
	// {
	// 	if (args->family == FAMILY_AF_INET)
	// 	{
	// 		int *nhsock = NULL;
	// 		nhsock = bpf_map_lookup_elem(&half_open_socket_map, (int *)args->daddr);
	// 		if (nhsock == NULL)
	// 		{
	// 			int num = 1;
	// 			if (bpf_map_update_elem(&half_open_socket_map, (int *)args->daddr, &num, BPF_ANY) != 0)
	// 			{
	// 				bpf_printk("update half socket map failed with error\n");
	// 			}
	// 		}
	// 		else
	// 		{
	// 			*nhsock++;
	// 			if (*nhsock > HALF_OPEN_SOCKET_LIMIT)
	// 			{
	// 				// todo: block ip address
	// 				return 0;
	// 			}
	// 			else
	// 			{
	// 				if (bpf_map_update_elem(&half_open_socket_map, (int *)args->daddr, nhsock, BPF_ANY) != 0)
	// 				{
	// 					bpf_printk("update half socket map failed with error\n");
	// 				}
	// 			}
	// 		}
	// 	}
	// 	else
	// 	{
	// 		// todo: handle ipv6
	// 		return 0;
	// 	}
	// }
	// if(args->dport == 8000)
	// 	return 0;
	// if (args->newstate == TCP_SYN_SENT || args->oldstate == TCP_SYN_SENT)
	// 	return 0;
	bpf_printk("state changed, socket_addr:%ld, dport:%d, old_state:%d, new_state:%d \n", (int64_t)args->skaddr, args->dport, args->oldstate, args->newstate);
	if ((args->newstate == TCP_SYN_RECV && args->oldstate == TCP_CLOSE))
	{
	}
	else if (args->newstate == TCP_ESTABLISHED)
	{
	}
	else
	{
		return 0;
	}
	return 0;
}

SEC("tracepoint/sock/inet_sk_error_report")
__attribute__((flatten)) int sock_error(void*args)
{
	bpf_printk("err\n");
}

SEC("tracepoint/tcp/tcp_retransmit_synack")
__attribute__((flatten)) int tcp_synack(void*args)
{
	bpf_printk("retransmit synack\n");
}
char __license[] SEC("license") = "GPL";