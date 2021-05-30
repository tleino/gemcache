#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void sendfile(const char *file, int fd)
{
	char *line = NULL;
	size_t sz = 0;
	ssize_t len;
	FILE *fp;

	syslog(LOG_ERR, "serve '%s'", file);
	if ((fp = fopen(file, "r")) == NULL) {
		syslog(LOG_ERR, "fopen: %m");
		return;
	}
	while ((len = getline(&line, &sz, fp)) != -1)
		write(fd, line, strlen(line));
	free(line);
	if (ferror(fp))
		syslog(LOG_ERR, "getline: %m");
	else
		fclose(fp);
}
