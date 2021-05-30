/*
 * Read arbitrary length data in optimal chunks and split to lines
 * as separated by CRLF or LF.
 *
 * For example:
 *   lb = linebuf_create();
 *
 *   while (linebuf_fill_from_tls(lb, tclient) > 0)
 *     while ((s = linebuf_read(lb)) != NULL)
 *       puts(s);
 *
 *   linebuf_free(lb);
 */

#include "linebuf.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tls.h>

#define READ_BUFFER_ALLOC 4096
#define READ_BUFFER_CHUNK 512

struct linebuf
{
	size_t alloc;	/* memory allocated for the buffer */
	size_t chunk;	/* read chunk size */
	size_t sz;	/* bytes currently in a line */
	size_t shrink;	/* shrink buffer by n bytes from beginning */
	char *buf;	/* line data */
};

static void linebuf_make_space(struct linebuf *);

struct linebuf *
linebuf_create()
{
	struct linebuf *line;

	line = calloc(1, sizeof(struct linebuf));
	if (line == NULL)
		err(1, "calloc");

	line->alloc = READ_BUFFER_ALLOC;
	line->chunk = READ_BUFFER_CHUNK;
	line->sz = 0;
	line->shrink = 0;
	if ((line->buf = malloc(line->alloc)) == NULL)
		err(1, "init_tls_line_buffer");	

	return line;
}

void
linebuf_free(struct linebuf *line)
{
	if (line->buf != NULL)
		free(line->buf);
	free(line);
}

static void
linebuf_make_space(struct linebuf *line)
{
	if (line->sz >= line->alloc - line->chunk) {
		line->alloc *= 2;
		line->buf = realloc(line->buf, line->alloc);
	}
}

int
linebuf_fill_from_tls(struct linebuf *line, struct tls *tclient)
{
	int n;

	linebuf_make_space(line);

	do {
		n = tls_read(tclient, &line->buf[line->sz], line->chunk);
	} while (n == TLS_WANT_POLLIN);

	if (n < 0)
		errx(1, "TLS read failed: %s", tls_error(tclient));
	if (n == 0)
		return 0;
	line->sz += n;
	return n;
}

char *
linebuf_read(struct linebuf *line)
{
	size_t i;

	if (line->shrink > 0) {
		line->sz -= line->shrink;
		if (line->sz >= 1)
			memmove(line->buf, &line->buf[line->shrink], line->sz);
		else
			line->sz = 0;
		line->shrink = 0;
		line->buf[line->sz] = '\0';
	}

	for (i = 0; i < line->sz; i++) {
		if (line->buf[i] != '\n')
			continue;
		if (i > 0 && line->buf[i-1] == '\r')
			line->buf[i-1] = '\0';

		line->buf[i] = '\0';
		line->shrink = (i + 1);

		return line->buf;
	}

	return NULL;
}
