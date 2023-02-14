#include "sock.h"

void SetInetAddr(struct sockaddr_in *addr, int port)
{
	int SOCK_LEN;
	SOCK_LEN = sizeof(addr);
	bzero((char *)addr, SOCK_LEN);
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;
	addr->sin_port = htons(port);
}

int BindSocket(int type, int port)
{
	int sd, SOCK_LEN;
	struct sockaddr_in addr;

	if ((sd = socket(AF_INET, type, 0)) < 0)
	{
		printf("[BindSocket] socket fail (port=%d) : %s\n",
			   port,
			   strerror(errno));
	}

	SetInetAddr(&addr, port);
	
	int reuse = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
        (char*)&reuse, sizeof(reuse)) < 0)
    {
        printf("Setting SO_REUSEADDR Error!!\n");
    }

	SOCK_LEN = sizeof(addr);
	if (bind(sd, (struct sockaddr *)&addr, SOCK_LEN) < 0)
	{
		printf("[BindSocket] bind fail (port=%d) : %s\n",
			   port,
			   strerror(errno));
	}


#if 0
	struct timeval read_timeout;
	read_timeout.tv_sec = 0;
	read_timeout.tv_usec = 10;
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,
			   &read_timeout, sizeof(read_timeout));
#endif
	return sd;
}