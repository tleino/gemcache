#include "fetch.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <err.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

static char *
find_cache_file(const char *hash)
{
	char *home;
	static char file[PATH_MAX];
	char *path, *dn;
	struct stat sb;

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

int
main(int argc, char *argv[])
{
	unsigned char hash[SHA_DIGEST_LENGTH + 1];
	int i;
	FILE *fp;
	char *file;
	char hstr[128 + 1], *p;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <url>\n", *argv);
		exit(1);
	}

	argv++;

	SHA1((unsigned char *) *argv, strlen(*argv), hash);
	hash[SHA_DIGEST_LENGTH] = '\0';
	p = hstr;
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(p, "%02x", hash[i]);
		p += 2;
	}
	*p = '\0';

	file = find_cache_file(hstr);
	fp = fopen(file, "r");
	if (fp == NULL) {
		fp = fopen(file, "w");
		fetch(*argv, fp);
	} else {
		printf("already available\n");
	}
	fclose(fp);

	return 0;
}
