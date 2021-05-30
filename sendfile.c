#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
void sendfile(const char *file, int fd)
{
	char buf[256];
	FILE *fp;

	syslog(LOG_ERR, "serve '%s'", file);
	if ((fp = fopen(file, "r")) == NULL) {
		syslog(LOG_ERR, "fopen: %m");
		return;
	}
	while (feof(fp) == 0) {
		buf[0] = '\0';
		fgets(buf, sizeof(buf), fp);
		buf[strcspn(buf, "\r\n")] = '\0';
		write(fd, buf, strlen(buf));
		write(fd, "\r\n", 2);
	}
	fclose(fp);
}
