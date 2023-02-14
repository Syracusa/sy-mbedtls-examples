#ifndef __SOCK_H__
#define __SOCK_H__

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <time.h>

void SetInetAddr(struct sockaddr_in *addr, int port);

int BindSocket(int type, int port);

#endif