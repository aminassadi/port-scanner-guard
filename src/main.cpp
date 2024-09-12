#include <iostream>
#include <bpf/libbpf.h>
#include "pscannerguard.skel.h"
#include <net/if.h>
#include "uapi/linux/if_link.h"

static void handle_terminate_signal(int sig)
{
}

int main(int argc, char **argv)
{
	auto skel = pscannerguard_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	auto err = pscannerguard_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return 0;
	}

	auto ifindex_list = if_nametoindex("ens33");
	auto xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
	// if (strncmp(argv[2], "--skb-mode", strlen(argv[2])) == 0)
	// 	xdp_flags |= XDP_FLAGS_SKB_MODE;
	// else
	// 	xdp_flags |= XDP_FLAGS_DRV_MODE;
	
	// err = bpf_xdp_attach(ifindex_list, bpf_program__fd(skel->progs.xdp_pass), xdp_flags, NULL);
	bpf_program__attach_tracepoint(skel->progs.TCPconnection, "sock", "inet_sock_set_state");
	bpf_program__attach_tracepoint(skel->progs.sock_error, "sock", "inet_sk_error_report");
	bpf_program__attach_tracepoint(skel->progs.tcp_synack, "tcp", "tcp_retransmit_synack");
	// if (ret == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
	// {
	// 	uint32_t old_flags = xdp_flags;

	// 	xdp_flags &= ~XDP_FLAGS_MODES;
	// 	xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
	// 	if (bpf_xdp_detach(ifindex_list, xdp_flags, NULL) == 0)
	// 	{
	// 		printf("try to attach xdp again...\n");
	// 		err = bpf_xdp_attach(ifindex_list, prog_fd, old_flags, NULL);
	// 	}
	// }
	/* Attach tracepoints */
	//err = pscannerguard_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return 0;
	}
	std::cin.get();
	bpf_xdp_detach(ifindex_list, xdp_flags, NULL);
	pscannerguard_bpf__destroy(skel);
	return 0;
}
