/*
 * based on http://beej.us/guide/bgnet/examples/client.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <arpa/inet.h>


#define MAXDATASIZE 100 // max number of bytes we can get at once 

#define MPTCP_MAX_ADDR 8 // XXX: copypasted from kernel headers

void print_subflows(int sockfd) {
	struct mptcp_subflow optval[MPTCP_MAX_ADDR];
	socklen_t optlen = sizeof optval;
	int res = getsockopt(sockfd, SOL_TCP, TCP_MULTIPATH_SUBFLOWS, &optval, &optlen);
	printf("optlen = %u\n", optlen);
	if (res != 0) {
		perror("getsockopt(..., TCP_MULTIPATH_SUBFLOWS,...)");
		return;
	}
	int num_subflows = optlen / sizeof(struct mptcp_subflow);
	if (num_subflows * sizeof(struct mptcp_subflow) != (unsigned)optlen) {
		printf("something went terribly wrong here. ABI problem? padding?\n");
		exit(1);
	}
	printf("Subflow list:\n");
	char loc_addr[INET6_ADDRSTRLEN];
	char rem_addr[INET6_ADDRSTRLEN];
	int i;
	for (i=0; i < num_subflows; i++) {

		if (optval[i].family == AF_INET) {
			inet_ntop(AF_INET, &optval[i].saddr, loc_addr, sizeof loc_addr);
			inet_ntop(AF_INET, &optval[i].daddr, rem_addr, sizeof rem_addr);
		} else if (optval[i].family == AF_INET6) {
			inet_ntop(AF_INET6, &optval[i].saddr6, loc_addr, sizeof loc_addr);
			inet_ntop(AF_INET6, &optval[i].daddr6, rem_addr, sizeof rem_addr);
		} else {
			exit(2);
		}
		printf("\t#% 2i: %s:%hu\t<->\t%s:%hu\n", i,
				loc_addr, ntohs(optval[i].sport),
				rem_addr, ntohs(optval[i].dport));
	}
	//hexDump("Subflows", optval, optlen);
}

void print_connid(int sockfd) {
	uint32_t optval = 0;
	socklen_t optlen = 23;
	int res = getsockopt(sockfd, SOL_TCP, TCP_MULTIPATH_CONNID, &optval, &optlen);
	printf("optlen = %u\n", optlen);
	if (res != 0) {
		perror("getsockopt(..., TCP_MULTIPATH_CONNID,...)");
		return;
	}
	if (optlen != sizeof(optval))
		return;
	printf("connid = %x\n", optval);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 3) {
		fprintf(stderr,"usage: mptcp_test <hostname> <port>\n");
		exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}
		printf("before connect:\n");
		print_connid(sockfd);
		print_subflows(sockfd);

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}
	printf("\n---\n");

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connected to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure


	print_connid(sockfd);
	print_subflows(sockfd);
	printf("sending some data...\n");
	char request[100];
	memset(request, 'A', sizeof request);
	send(sockfd, request, sizeof request, 0);
	print_subflows(sockfd);
	printf("sleep 1...\n");
	sleep(1);
	print_subflows(sockfd);

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
		perror("recv");
		exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);

	close(sockfd);

	return 0;
}

