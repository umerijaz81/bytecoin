#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*getaddrinfo_function)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
	const char *forbidden = getenv("BYTECOIN_DNS_FORBIDDEN_HOST");
	if (node != NULL && forbidden != NULL && strcmp(node, forbidden) == 0) {
		const char *marker = getenv("BYTECOIN_DNS_GUARD_MARKER");
		if (marker != NULL) {
			FILE *file = fopen(marker, "wb");
			if (file != NULL) {
				fputs(node, file);
				fclose(file);
			}
		}
		return EAI_FAIL;
	}
	getaddrinfo_function next = (getaddrinfo_function)dlsym(RTLD_NEXT, "getaddrinfo");
	if (next == NULL)
		return EAI_SYSTEM;
	return next(node, service, hints, result);
}
