// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#define SOCK_PATH "/tmp/my_socket"


#include "ipc.h"


int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}
	return sockfd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("connect");
		return -1;
	}
	return 0;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	size_t bytes_sent = send(fd, buf, len, 0);
	if (bytes_sent < 0) {
		perror("send");
		return -1;
	}
	return bytes_sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	size_t bytes_recv = recv(fd, buf, len, 0);
	if (bytes_recv < 0) {
		perror("recv");
		return -1;
	}
	return bytes_recv;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
	if (close(fd) < 0) {
		perror("close");
	}
}
