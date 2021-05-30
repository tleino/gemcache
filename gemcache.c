#include "fetch.h"
#include "tcpbind.h"
#include "serve.h"

#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <err.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>

static char *
hash_url(const char *url)
{
	static char		 hstr[128];
	unsigned char		 hash[SHA_DIGEST_LENGTH + 1];
	char			*p;
	int			 i;

	SHA1((unsigned const char *) url, strlen(url), hash);
	hash[SHA_DIGEST_LENGTH] = '\0';
	p = hstr;
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(p, "%02x", hash[i]);
		p += 2;
	}
	*p = '\0';

	return hstr;	
}

char *
find_cache_file(const char *url)
{
	char			*home;
	static char		 file[PATH_MAX];
	char			*path, *dn;
	struct stat		 sb;
	char			*hash;

	hash = hash_url(url);

	home = getenv("HOME");
	if (home == NULL)
		err(1, "getenv HOME");

	if (snprintf(file, sizeof(file), "%s/.gemcache/%s",
	    home, hash) >= sizeof(file))
		errx(1, "bogus HOME variable?");

	path = strdup(file);
	if (path == NULL)
		err(1, "strdup %s", file);
	dn = dirname(path);
	if (dn == NULL)
		err(1, "dirname %s", file);
	if (stat(dn, &sb) != 0) {
		if (errno == ENOENT) {
			warnx("create %s", dn);
			if (mkdir(dn, 0700) != 0)
				warnx("mkdir %s", dn);
		} else
			err(1, "stat %s", dn);
	}
	free(path);

	return file;	
}

void session(int);

int
main(int argc, char *argv[])
{
	int			 sfd;

	openlog(argv[0], 0, LOG_DAEMON);

	sfd = tcpbind("0.0.0.0", 1965);

	for (;;) {
		int fd, status;
		pid_t pid;

		fd = serve(sfd);
		if (fd < 0)
			continue;
		if ((pid = fork()) == 0) {
			alarm(10);	/* session expire time */
#ifdef __OpenBSD__
			setproctitle("session");
#endif
			session(fd);
			_exit(127);
		}
		close(fd);
		if (pid != -1)
			wait(&status);
	}


	return 0;
}
