// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ipc.h"
#include "server.h"
#define BUFLEN 256

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
    // Load the library dynamically
    lib->handle = dlopen(lib->libname, RTLD_NOW);
    if (lib->handle == NULL) {
        fprintf(stderr, "Error loading library: %s\n", dlerror());
        return 1;
    }

    // Obtain function pointers
    lib->run = (lambda_func_t)dlsym(lib->handle, lib->funcname);
    if (lib->run == NULL) {
        fprintf(stderr, "Error obtaining function pointer: %s\n", dlerror());
        dlclose(lib->handle);
        return 1;
    }
    return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	lib->outputfile = malloc(strlen(OUTPUT_TEMPLATE) + 1);
	strcpy(lib->outputfile, OUTPUT_TEMPLATE);
	int fd = mkstemp(lib->outputfile);
	if (fd < 0) {
		perror("mkstemp");
		return -1;
	}
	close(fd);
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	if (lib->run != NULL) {
		lib->p_run(lib->outputfile);
	} else {
		lib->run();
	}
	
	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	if (dlclose(lib->handle) < 0) {
		fprintf(stderr, "Error closing library: %s\n", dlerror());
		return 1;
	}
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	free(lib->outputfile);

	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s [%s [%s]]", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	/* TODO - get message from client */
	/* TODO - parse message with parse_command and populate lib */
	/* TODO - handle request from client */
	int sockfd = create_socket();
	if (sockfd < 0) {
		return 1;
	}
	if (bind_socket(sockfd) < 0) {
		return 1;
	}
	if (listen_socket(sockfd) < 0) {
		return 1;
	}
	int clientfd = accept_socket(sockfd);
	if (clientfd < 0) {
		return 1;
	}
	char buf[BUFLEN];
	memset(buf, 0, BUFLEN);
	ssize_t bytes_recv = recv_socket(clientfd, buf, BUFLEN);
	if (bytes_recv < 0) {
		return 1;
	}
	struct lib lib;
	memset(&lib, 0, sizeof(lib));
	int ret = parse_command(buf, lib.libname, lib.funcname, lib.filename);
	if (ret < 0) {
		return 1;
	}
	lib.p_run = (lambda_func_t)dlsym(lib.handle, lib.funcname);
	if (lib.p_run == NULL) {
		fprintf(stderr, "Error obtaining function pointer: %s\n", dlerror());
		return 1;
	}
	lib_run(&lib);
	if (send_file(clientfd, lib.outputfile) < 0) {
		return 1;
	}
	close_socket(clientfd);
	close_socket(sockfd);


	return 0;
}
