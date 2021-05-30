#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <sys/socket.h>

int
serve(int sfd)
{
	int fd;
	struct sockaddr_in a;
	socklen_t sz = sizeof(a);

	fd = accept(sfd, (struct sockaddr *) &a, &sz);
	if (fd < 0 && errno != EINTR)
		syslog(LOG_ERR, "accept: %m");
	else
		syslog(LOG_ERR, "accept %s", inet_ntoa(a.sin_addr));
	return fd;
}
