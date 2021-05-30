#ifndef TOFU_H
#define TOFU_H

enum tofu_status {
	TOFU_INVALID, TOFU_NEW_HOST, TOFU_VALID
};

struct tls;

int					 tofu_is_known(const char *);
enum tofu_status			 tofu_check(struct tls *);
void					 tofu_save(struct tls *);

#endif
