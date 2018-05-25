/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_flow_classify.h>
#include <rte_table_acl.h>

#include <libtstat.h>

#include "bloom_filter.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512
#define SCHED_TX_RING_SZ 65536

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_NUM_CLASSIFY 30
#define FLOW_CLASSIFY_MAX_RULE_NUM 91
#define FLOW_CLASSIFY_MAX_PRIORITY 8
#define FLOW_CLASSIFIER_NAME_SIZE 64

// #define DEBUG 1

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* Received packet counting */
static uint64_t total_pkt_count;

#define BF_MAX_BIT 4096
#define BF_MAX_HASH_NUM 3
#define KEY_BYTE_SIZE 16

/* Based on DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct ether_addr addr;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and processing the packets.
 */
static __attribute__((noreturn)) void
lcore_main(struct rte_ring *rcv_ring)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	// int ret;
	// int i = 0;
	struct timeval tv_begin, tv_end;
	int start = 0;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
			printf("\n\n");
			printf("WARNING: port %u is on remote NUMA node\n",
			       port);
			printf("to polling thread.\n");
			printf("Performance will not be optimal.\n");

			printf("\nCore %u forwarding packets. ",
			       rte_lcore_id());
			printf("[Ctrl+C to quit]\n");
		}
	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port, classify them and forward them.
		 */
		for (port = 0; port < nb_ports; port++) {
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (start == 0 && nb_rx > 0) {
				start = 1;
				gettimeofday(&tv_begin, NULL);
			}
			if (total_pkt_count >= 9900000) {
				gettimeofday(&tv_end, NULL);
				printf("elscaped time:%lu.%lu\n",
					tv_end.tv_sec - tv_begin.tv_sec,
					tv_end.tv_usec - tv_begin.tv_usec);
				exit(0);
			}

			if (unlikely(nb_rx == 0))
				continue;

#ifdef DEBUG
			printf("nb_rx = %d\n", nb_rx);
#endif
			total_pkt_count += nb_rx;
			rte_ring_enqueue_burst(rcv_ring,
				(void *)bufs, nb_rx, NULL);

			// const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
			// 		bufs, nb_rx);

			/* Free any unsent packets. */
			// if (unlikely(nb_tx < nb_rx)) {
			// 	uint16_t buf;

			// 	for (buf = nb_tx; buf < nb_rx; buf++)
			// 		rte_pktmbuf_free(bufs[buf]);
			// }
		}
	}
}

/*
 * The process running tstat application and settling down
 * receiving packets.
 */
static int
tstat_process(__attribute__((unused)) struct rte_ring *rcv_ring)
{
	struct timeval tv;
	struct rte_mbuf *bufs[BURST_SIZE*4];
	uint32_t i;

	printf("Hello World from core %u.\n", rte_lcore_id());
	for (;;) {
		const uint16_t nb_rx = rte_ring_dequeue_burst(rcv_ring,
				(void *)bufs, BURST_SIZE, NULL);
		if (nb_rx) {
			for (i = 0; i < nb_rx; ++i) {
				tstat_next_pckt(&(tv), 
				(void *)(rte_pktmbuf_mtod(bufs[i], char*) + 
				sizeof(struct ether_hdr)), 
				rte_pktmbuf_mtod(bufs[i], char*) +
				rte_pktmbuf_data_len(bufs[i]) - 1,
				(rte_pktmbuf_data_len(bufs[i]) -
				 sizeof(struct ether_hdr)), 0);
			}
			for (i = 0; i < nb_rx; ++i) {
				rte_pktmbuf_free(bufs[i]);
			}
		}
	}
	return 0;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case 0:
			break;
		default:
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Signal handling function */
static void
sig_handler(int signo)
{
	/* catch signal */
	if (signo == SIGTERM || signo == SIGINT) {
		tstat_report report;
		tstat_close(&report);
		tstat_print_report(&report, stdout);
		printf("Total number of received packet: %lu\n",
				total_pkt_count);
		exit(0);
	}
}

/*
 * The main function, which does initialization and calls the lcore_main
 * function.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint8_t nb_ports;
	uint8_t portid;
	int ret;
	struct rte_ring * rcv_ring;
	unsigned int socket_id = 1;
	char * conf_file = strdup("tstat.conf");
	char * tstat_log = strdup("logs");

	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);

	/* Initialize the Environment Abstraction Layer (EAL). */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid flow_classify parameters\n");

	/*
	 * Check that there is an enough number of lcore
	 * to run tstat application.
	 */
	if (rte_lcore_count() < 2) {
		rte_exit(EXIT_FAILURE, "Error: Too few lcores enabled."
				"There needs at least two lcores.\n");
	}

	/* Check that there is an enough number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports < 1)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be enough\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	if (rte_lcore_count() < 2) {
		rte_exit(EXIT_FAILURE, "Too few lcores enabled. At least two lcores\n");
	}

	printf("======================\n");

	struct timeval tv;
	gettimeofday(&tv, NULL);
	tstat_init(conf_file);
	tstat_new_logdir(tstat_log, &tv);

	rcv_ring = rte_ring_create("Tstat_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rcv_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create receiving ring\n");

	/*
	 * Launch a remote lcore to run tstat
	 * on core 1.
	 */
	rte_eal_remote_launch((lcore_function_t *)tstat_process,
			rcv_ring, socket_id);

	/* Call lcore_main on the master core only. */
	/* This function distributes the traffic to all kind of categories. */
	lcore_main(rcv_ring);

	return 0;
}
