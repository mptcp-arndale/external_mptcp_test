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


void hexDump (char *desc, void *addr, int len) {
	// source: http://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
	int i;
	unsigned char buff[17];
	unsigned char *pc = addr;

	// Output description if given.
	if (desc != NULL)
		printf ("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf ("  %s\n", buff);

			// Output the offset.
			printf ("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf (" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf ("   ");
		i++;
	}
}

void print_subflows(int sockfd) {
#define OPTVAL_MAX 1000
	unsigned char optval[OPTVAL_MAX];
	socklen_t optlen = sizeof optval;
	int res = getsockopt(sockfd, SOL_TCP, TCP_MULTIPATH_SUBFLOWS, &optval, &optlen);
	printf("optlen = %u\n", optlen);
	if (res != 0) {
		perror("getsockopt(..., TCP_MULTIPATH_SUBFLOWS,...)");
		close(sockfd);
		return;
	}
	hexDump("Subflows", optval, optlen);
}

void print_connid(int sockfd) {
	uint32_t optval = 0;
	socklen_t optlen = 23;
	int res = getsockopt(sockfd, SOL_TCP, TCP_MULTIPATH_CONNID, &optval, &optlen);
	printf("optlen = %u\n", optlen);
	if (res != 0) {
		perror("getsockopt(..., TCP_MULTIPATH_CONNID,...)");
		close(sockfd);
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

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
		perror("recv");
		exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);

	close(sockfd);

	return 0;
}

