#include "tofu.h"

#include <err.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <libgen.h>
#include <tls.h>

static char *
find_known_hosts()
{
	char *home;
	static char file[PATH_MAX];
	char *path, *dn;
	struct stat sb;

	home = getenv("HOME");
	if (home == NULL)
		err(1, "getenv HOME");

	if (snprintf(file, sizeof(file), "%s/.gemcache/known_hosts",
	    home) >= sizeof(file))
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

struct certval
{
	char servername[128 + 1];
	char hash[256 + 1];
	time_t notbefore;
	time_t notafter;
};

static struct certval
tofu_certval(struct tls *ctx)
{
	struct certval cv;
	const char *servername, *hash;

	servername = tls_conn_servername(ctx);
	if (servername == NULL)
		errx(1, "could not figure TLS server name");
	cv.notbefore = tls_peer_cert_notbefore(ctx);
	cv.notafter = tls_peer_cert_notafter(ctx);
	if (cv.notbefore == -1 || cv.notafter == -1)
		errx(1, "could not determine TLS cert validity range");
	hash = tls_peer_cert_hash(ctx);
	if (hash == NULL)
		errx(1, "could not make TLS cert hash");
	if (strlcpy(cv.servername, servername, sizeof(cv.servername)) >=
		sizeof(cv.servername))
		errx(1, "truncated servername");
	if (strlcpy(cv.hash, hash, sizeof(cv.hash)) >=
		sizeof(cv.hash))
		errx(1, "truncated hash");

	return cv;
}

static int
tofu_find_host(const char *host, struct certval *retcv)
{
	FILE *fp;
	char *file;
	int lno = 0;
	int ret;
	struct certval cv;
	time_t t;

	file = find_known_hosts();
	fp = fopen(file, "r");
	if (fp == NULL)
		return 0;

	t = time(NULL);
	memset(retcv, '\0', sizeof(struct certval));
	while ((ret = fscanf(fp, "%128s %lld %lld %256s",
	    cv.servername, &cv.notbefore, &cv.notafter, cv.hash)) != EOF) {
		if (ret != 4)
			errx(1, "%s: parse error on line %d", file, lno + 1);
		if (strcmp(host, cv.servername) == 0 &&
		    t >= cv.notbefore && t < cv.notafter)
			*retcv = cv;
		lno++;
	}
	if (ferror(fp)) {
		fclose(fp);
		return 0;
	}
	fclose(fp);
	if (*retcv->servername == '\0')
		return 0;

	return 1;
}

int
tofu_is_known(const char *host)
{
	struct certval cv;

	if (tofu_find_host(host, &cv) == 1)
		return 1;
	return 0;
}

/*
 * This algorithm disregards normal CA-based certificate validation
 * but depends on the hash and the validity time range. If previous
 * certificate was already expired, new certificate is automatically
 * trusted.
 */
enum tofu_status
tofu_check(struct tls *ctx)
{
	struct certval ref, cv;
	time_t t;

	t = time(NULL);
	ref = tofu_certval(ctx);

	if (t < ref.notbefore || t >= ref.notafter)
		return TOFU_INVALID;
	if (tofu_find_host(ref.servername, &cv) == 0)
		return TOFU_NEW_HOST;
	if (strcmp(ref.hash, cv.hash) != 0)
		return TOFU_INVALID;

	return TOFU_VALID;
}

void
tofu_save(struct tls *ctx)
{
	FILE *fp;
	char *file;
	struct stat sb;
	struct certval cv;

	file = find_known_hosts();

	if (stat(file, &sb) != 0) {
		if (errno == ENOENT)
			warnx("create %s", file);
		else
			err(1, "stat %s", file);
	}
	fp = fopen(file, "a");
	if (fp == NULL)
		err(1, "fopen %s", file);

	cv = tofu_certval(ctx);
	fprintf(fp, "%s %lld %lld %s\n",
	    cv.servername, cv.notbefore, cv.notafter, cv.hash);
	fclose(fp);
}
