// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


#include "ipc.h"


int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sockfd;

    // Create a socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    return sockfd;
}

int bind_socket(int fd)
{
	struct sockaddr_un addr;
	// Remove any existing file at the socket path
    unlink(SOCKET_NAME);

    // Set up the address structure
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);

    // Bind the socket to the address
    if (bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        close(fd);
        return -1;
    }

	return 0;
}

int listen_socket(int fd)
{
	if (listen(fd, 5) == -1) {
		perror("listen");
		close(fd);
		unlink(SOCKET_NAME);
		return -1;
	}
	return 0;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
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

int accept_connection(int sockfd)
{
    struct sockaddr_un addr;
    socklen_t addrlen;

    // Accept a connection
    addrlen = sizeof(struct sockaddr_un);
    int newsockfd = accept(sockfd, (struct sockaddr*)&addr, &addrlen);
    if (newsockfd == -1) {
        perror("accept");
        return -1;
    }

    return newsockfd;
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
