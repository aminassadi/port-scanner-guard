#include <iostream>
#include <bpf/libbpf.h>
#include "pscannerguard.skel.h"

static void handle_terminate_signal(int sig)
{
}

int main(int argc, char **argv)
{
    auto skel = pscannerguard_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}


	auto err = pscannerguard_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return 0;
	}

	/* Attach tracepoints */
	err = pscannerguard_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return 0;
	}
    std::cin.get();
    pscannerguard_bpf__destroy(skel);
    return 0;
}
