#include <stdio.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[])
{
	printf("TODO: implement test\n");
#ifdef TCP_MULTIPATH_CONNID
	printf("TCP_MULTIPATH_CONNID is known: %u\n", TCP_MULTIPATH_CONNID);
#else
	printf("TCP_MULTIPATH_CONNID unknown\n");
#endif
	return 0;
}
