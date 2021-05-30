#include "fetch.h"
#include "url.h"
#include "tofu.h"
#include "linebuf.h"

#include <tls.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>

static void write_line(struct tls *, const char *);

struct session
{
	struct tls_config	*tconf;
	struct tls		*tclient;
	struct linebuf		*lb;
	char			*firstline;
};

struct session *
fetch_open(const struct url *url, int *code, char **firstline)
{
	char *s, *p;
	struct session *sess;
	int tries;

	sess = calloc(1, sizeof(struct session));
	if (sess == NULL)
		return NULL;

	sess->tconf = tls_config_new();
	if (sess->tconf == NULL)
		return NULL;

	sess->tclient = tls_client();
	if (sess->tclient == NULL)
		return NULL;

	tries = 2;
	while (tries--) {
		if (tofu_is_known(url->host)) {
			tls_config_insecure_noverifycert(sess->tconf);
			tries = 0;
		}
		if (tls_configure(sess->tclient, sess->tconf) == -1) {
			warnx("%s",
			    tls_config_error(sess->tconf));
			return NULL;
		}
		if (tls_connect(sess->tclient, url->host, url->port) == -1) {
			warnx("%s", tls_error(sess->tclient));
			return NULL;
		}
		if (tls_handshake(sess->tclient) == -1) {
			warnx("%s", tls_error(sess->tclient));
			tls_config_insecure_noverifycert(sess->tconf);
			if (!tries)
				return NULL;
		}
	}

	switch (tofu_check(sess->tclient)) {
	case TOFU_VALID:
		break;
	case TOFU_NEW_HOST:
		tofu_save(sess->tclient);
		break;
	case TOFU_INVALID:
	default:
		errx(1, "Check certificate");
	}

	write_line(sess->tclient, url_str(url, NULL));

	sess->lb = linebuf_create();

	s = NULL;
	while (linebuf_fill_from_tls(sess->lb, sess->tclient) > 0)
		if ((s = linebuf_read(sess->lb)) != NULL)
			break;
	if (s == NULL) {
		warnx("couldn't read first line");
		return NULL;
	}
	p = strchr(s, ' ');
	if (p != NULL) {
		*p++ = '\0';
		sess->firstline = strdup(p);
		*code = atoi(s);
	}
	*firstline = sess->firstline;

	return sess;
}

void
fetch_close(struct session *sess)
{
	if (sess->tclient != NULL) {
		tls_close(sess->tclient);
		tls_free(sess->tclient);
	}

	if (sess->tconf != NULL)
		tls_config_free(sess->tconf);

	if (sess->firstline != NULL)
		free(sess->firstline);
	
	free(sess);
}

void
fetch_linestream(struct session *sess,
    void (*linecb)(const char *line, void *data), void *data)
{
	char *s;

	while (linebuf_fill_from_tls(sess->lb, sess->tclient) > 0)
		while ((s = linebuf_read(sess->lb)) != NULL)
			linecb(s, data);

	linebuf_free(sess->lb);
}

static void
linecb(const char *s, void *data)
{
	FILE *fp = (FILE *) data;

	fprintf(fp, "%s\n", s);
}

int
fetch(const char *s, FILE *fp)
{	
	struct session *sess;
	int status;
	char *meta;
	struct url url;
	char *ustr;
	int ret;
	char *p;

	ustr = strdup(s);
	if (ustr == NULL)
		err(1, "strdup");

	if (url_parse(&url, ustr) == -1)
		errx(1, "error parsing: %s", s);

	if (strcmp(url.scheme, "gemini") != 0)
		errx(1, "unsupported scheme: %s", url.scheme);

	sess = fetch_open(&url, &status, &meta);
	if (sess == NULL)
		errx(1, "couldn't connect: %s", s);

	if (status >= 10 && status <= 19) {
		errx(1, "requires input");
	} else if (status >= 30 && status <= 39) {
		printf("redirect %s\n", meta);
		p = strdup(meta);
		fetch_close(sess);
		ret = fetch(p, fp);
		free(p);
		return ret;
	} else if (status >= 40 && status <= 49) {
		errx(1, "temp failure: %s", meta);
	} else if (status >= 50 && status <= 59) {
		errx(1, "permanent failure: %s", meta);
	} else if (status >= 60 && status <= 69) {
		errx(1, "client certificate required");
	} else if (status < 20 || status > 29) {
		errx(1, "unsupported status: %d", status);
	}

	if (strncmp(meta, "text/gemini", strlen("text/gemini")) == 0 ||
	    strncmp(meta, "text/plain", strlen("text/plain")) == 0)
		fetch_linestream(sess, linecb, fp);
	else {
		errx(1, "unsupported type: %s", meta);
	}

	fetch_close(sess);
	return 0;
}

static void
write_line(struct tls *tclient, const char *str)
{
	size_t len, newlen;
	ssize_t ret;
	const char *p;
	char *s;

	len = strlen(str);
	newlen = len + strlen("\r\n");
	if ((s = malloc(newlen + 1)) == NULL)
		err(1, "malloc");
	
	strlcpy(s, str, newlen);
	s[newlen-2] = '\r';
	s[newlen-1] = '\n';
	s[newlen] = '\0';

	len = newlen;
	p = s;
	while (len > 0) {
		ret = tls_write(tclient, p, len);
		if (ret == TLS_WANT_POLLOUT)
			continue;
		if (ret == -1)
			errx(1, "tls_write: %s", tls_error(tclient));
		p += ret;
		len -= ret;
	}

	free(s);
}
