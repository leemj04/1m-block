#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <set>

#include <sys/sysinfo.h>

#include "packethdr.h"

clock_t elapsed;
float   sec;
#define START_TIME \
{\
    elapsed = -clock();\
}
#define STOP_TIME \
{\
    elapsed += clock();\
	sec = (float)elapsed/CLOCKS_PER_SEC;\
}
#define PRINT_TIME(str) \
{\
    printf("\n[%-23s: %2.5f s]\n\n",str,sec);\
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		// printf("hw_protocol=0x%04x hook=%u id=%u ",
		//  	ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);
		/*
		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		*/
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		// printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		// printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		// printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		// printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		// printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		// printf("payload_len=%d\n", ret);
		// dump(data, ret);
	}

	// fputc('\n', stdout);

	return id;
}

char num;
std::set<std::string> host;

char *strnstr(const char *s, char *find, int slen) {
	char c, sc;
	int len = strlen(find);

	if (len == 0)
		return (char *)s;

	char *new_s = (char *)malloc(slen + 1);
	strncpy(new_s, s, slen);
	new_s[slen] = '\0';

	char *ret = strstr(new_s, find);
	free(new_s);

	return ret;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data) {
	u_int32_t id = print_pkt(nfa);
	// printf("entering callback\n");

	unsigned char *d;
	int ret = nfq_get_payload(nfa, &d);
	char *site = NULL;

	IpHdr *ip = (IpHdr *)d;
	if (ip->protocol != 0x06) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	TcpHdr *tcp = (TcpHdr *)(d + sizeof(IpHdr));
	const char *http = (const char *)(d + sizeof(IpHdr) + tcp->th_off * 4);

	if (ntohs(tcp->th_dport) == 80 && strncmp(http, "GET", 3) == 0 && (site = strnstr(http, "Host: ", 50)) != NULL) {
		START_TIME;
		std::string site_str(site + 6);
		std::istringstream ss(site_str);
		getline(ss, site_str, '\r');

		if (host.find(site_str) != host.end()) {
			printf("%s Blocked\n\n", site_str.c_str());
			STOP_TIME;
			PRINT_TIME("Search Block Site");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}

		STOP_TIME;
		PRINT_TIME("Search Block Site");
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void print_sysinfo(struct sysinfo *sys, unsigned long *ram) {
	printf("\n");
	printf("Uptime              : %ld\n", sys->uptime);
	printf("Total RAM           : %lu\n", sys->totalram);
	printf("Free RAM            : %lu\n", sys->freeram);
	printf("Shared RAM          : %lu\n", sys->sharedram);
	printf("Buffer RAM          : %lu\n", sys->bufferram);
	printf("Total Swap          : %lu\n", sys->totalswap);
	printf("Free Swap           : %lu\n", sys->freeswap);
	printf("Number of processes : %u\n", sys->procs);
	printf("\n");

	*ram = sys->totalram - sys->freeram;
}

int main(int argc, char **argv) {
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	struct sysinfo info;
	unsigned long before_ram, after_ram;

	printf("<before load>\n");
	sysinfo(&info);
	print_sysinfo(&info, &before_ram);

	if (argc != 2) {
		printf("syntax : 1m-block <site list file>\n");
		printf("sample : 1m-block top-1m.csv\n");
		return 0;
	}

	num = argc;

	START_TIME;
	std::fstream fp;
	fp.open(argv[1], std::ios::in);

	if (!fp) {
		printf("No such %s file\n", argv[1]);
		return 0;
	}

	while(!fp.eof()) {
		std::string line1, line2;
		std::getline(fp, line1, ',');
		std::getline(fp, line2, '\n');
		host.insert(line2);
	}

	fp.close();
	STOP_TIME;
	PRINT_TIME("Read File and Load");

	printf("%ld sites loaded\n", host.size());

	printf("<after load>\n");
	sysinfo(&info);
	print_sysinfo(&info, &after_ram);

	printf("Used RAM            : %lu\n", after_ram - before_ram);
	printf("\n");

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

