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
	/* TODO: Implement lib_prehooks(). */
	if (lib->outputfile != NULL) {
		lib->output_file_ptr = fopen(lib->outputfile, "w");
		if (lib->output_file_ptr == NULL) {
			return -1;
		}
	} else {
		lib->output_file_ptr = NULL;
	}

	if (lib->filename != NULL) {
		lib->input_file_ptr = fopen(lib->filename, "r");
		if (lib->input_file_ptr == NULL) {
			return -1;
		}
	} else {
		lib->input_file_ptr = NULL;
	}

	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	if (lib->libname == NULL) {
		return -1;
	}

	lib->handle = dlopen(lib->libname, RTLD_NOW);
	if (lib->handle == NULL) {
		return -1;
	}
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */

	if (lib->funcname == NULL) {
		// executex RUN daca nu exista funcname

		lib->run = dlsym(lib->handle, "run");
		lib->run();
	} else if (lib->input_file_ptr == NULL) {
		// asta inseamna ca nu am fisier de input, ceea ce inseamna ca apelez lambda fara parametrii
		lib->run = dlsym(lib->handle, lib->funcname);
		lib->run();
	} else {
		// suntem in cazul in care avem fisier de input, ceea ce inseamna ca vrem sa apelam lambda cu parameterii

		lib->p_run = dlsym(lib->handle, lib->funcname);

		const char *name;
		const char *func;
		const char *params;

		parse_command(lib->filename, name, func, params);

		lib->p_run(params);
	}

	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	dlclose(lib->handle);
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	fclose(lib->input_file_ptr);
	fclose(lib->output_file_ptr);
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

		ret = send_socket(newsockfd, lib.filename, strlen(lib.filename));
		if (ret < 0) {
			perror("send_socket");
			return -1;
		}

		/* TODO - handle request from client */
		// ret = lib_run(&lib);
	}

	/* TODO - close socket */
	close_socket(fd);

	return 0;
}
