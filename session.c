#include "fetch.h"
#include <stdlib.h>
#include <syslog.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void sendfile(const char *file, int fd);
char *find_cache_file(const char *hash);
int validselector(const char *selector, const char *host);
const char *makesafe(const char *p);

/* session: serve a client */
void session(int fd)
{
	char c, buf[256];
	size_t len;
	int n;
	const char *file;
	FILE *fp;

	/* read selector */
	len = 0;
	while ((n = read(fd, &c, sizeof(char))) > 0) {
		if (c == '\r' || c == '\n')
			break;
		buf[len++] = c;
		if (len+1 == sizeof(buf))
			break;
	}
	if (n <= 0)
		return;
	buf[len] = '\0';

	file = find_cache_file(buf);
	fp = fopen(file, "r");

	if (fp == NULL) {
		fp = fopen(file, "w");
		fetch(buf, fp);
		fclose(fp);
	} else
		fclose(fp);

	sendfile(file, fd);
}
