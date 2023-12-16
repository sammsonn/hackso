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

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

int parse_command(const char *buf, char *name, char *func, char *params);

static int lib_prehooks(struct lib *lib)
{
	// TODO: Implement lib_prehooks().
	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (lib->handle == NULL) {
		fprintf(stderr, "Error opening library: %s\n", dlerror());
		return 1;
	}

	lib->p_run = dlsym(lib->handle, lib->funcname);
	if (lib->p_run == NULL) {
		fprintf(stderr, "Error loading function: %s\n", dlerror());
		return 1;
	}

	lib->outputfile = malloc(1024 * (BUFSIZE + 1));
	memset(lib->outputfile, 0, 1024 * (BUFSIZE + 1));
	strncpy(lib->outputfile, OUTPUT_TEMPLATE, strlen(OUTPUT_TEMPLATE));


	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	lib->run = dlsym(lib->handle, lib->funcname);
	if (lib->run == NULL) {
		fprintf(stderr, "Error loading function: %s\n", dlerror());
		return 1;
	}

	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	if (strlen(lib->funcname) == 0) {
		lib->funcname = "run";
		lib->run = dlsym(lib->handle, "run");
		int fd = open(lib->outputfile, O_CREAT | O_WRONLY, 0644);
		if (fd < 0) {
			perror("open");
			return 1;
		}
		dup2(fd, 1);
		lib->run();
	} else if (lib->filename[0] == 0) {
		lib->run = dlsym(lib->handle, lib->funcname);
		int fd = open(lib->outputfile, O_CREAT | O_WRONLY, 0644);
		if (fd < 0) {
			perror("open");
			return 1;
		}
		dup2(fd, 1);

		lib->run();
	} else {
		lib->p_run = dlsym(lib->handle, lib->funcname);
		int fd = open(lib->outputfile, O_CREAT | O_WRONLY, 0644);
		if (fd < 0) {
			perror("open");
			return 1;
		}
		dup2(fd, 1);
		lib->p_run(lib->filename);
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
	free(lib->libname);
	free(lib->funcname);
	free(lib->filename);

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
	return 0;
}

int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;
	ret = sscanf(buf, "%s %s %s", name, func, params);

	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	int ret;
	struct lib lib;
	int fd = -1;

	lib.libname = malloc(128 * (BUFSIZE + 1));
	lib.funcname = malloc(128 * (BUFSIZE + 1));
	lib.filename = malloc(1024 * (BUFSIZE + 1));

	fd = create_socket();
	if (fd < 0) {
		perror("create_socket");
		return -1;
	}
	ret = bind_socket(fd);
	if (ret < 0) {
		perror("bind_socket");
		return -1;
	}
	ret = listen_socket(fd);
	if (ret < 0) {
		perror("listen_socket");
		return -1;
	}

	while (1) {
		/* TODO - get message from client */
		int newsockfd = accept_connection(fd);
		if (newsockfd == -1) {
			perror("accept_connection");
			return -1;
		}

		char buf[BUFSIZE];
		memset(buf, 0, BUFSIZE);
		recv_socket(newsockfd, buf, BUFSIZE);
		buf[BUFSIZE - 1] = 0;

		/* TODO - parse message with parse_command and populate lib */
		ret = parse_command(buf, lib.libname, lib.funcname, lib.filename);
		if (ret < 0) {
			perror("parse_command");
			return -1;
		}

		if(strcmp(lib.libname, "exit") == 0) {
			break;
		}

		else if(lib.filename[0] == 0) {
			lib.filename = buf;
		}

		ret = send_socket(newsockfd, lib.filename, strlen(lib.filename));
		if (ret < 0) {
			perror("send_socket");
			return -1;
		}

		/* TODO - handle request from client */
		ret = lib_run(&lib);
		
	}

	/* TODO - close socket */
	close_socket(fd);

	return 0;
}