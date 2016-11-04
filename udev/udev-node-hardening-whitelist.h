#ifndef _UDEV_NODE_HARDENING_WHITELIST_
#define _UDEV_NODE_HARDENING_WHITELIST_

#include "udev-hardening-utils.h"

#ifndef END_NODE_HARDENING_WHITELIST_ELEMENT
# define END_NODE_HARDENING_WHITELIST_ELEMENT { NULL, 0000, 0, 0, 0, 0 }
#endif /* END_NODE_HARDENING_WHITELIST_ELEMENT */


#ifndef END_NODE_HARDENING_WHITELIST
# define END_NODE_HARDENING_WHITELIST(x) (x.path == NULL && x.mode == 0000)
#endif /* END_NODE_HARDENING_WHITELIST */

#ifndef WN
# define WN(node) { #node, 0000, 0, 0, 0, 0 }
#endif


struct node_hardening_whitelist_t {
	char  *path;
	mode_t mode;
	int    major;
	int    minor;
	uid_t  uid;
	gid_t  gid;
};

/* is the device allowed or not
 *
 * return: 0 = not allowed
 * otherwise = allowed
 */
static int __hardening_is_allowed_device(const char *path, const int major, const int minor, const mode_t mode, const uid_t uid, const gid_t gid);

static const struct node_hardening_whitelist_t __hardening_node_whitelist[] = {
	END_NODE_HARDENING_WHITELIST_ELEMENT
};

static int __hardening_is_allowed_device(const char *path, const int major, const int minor, const mode_t mode, const uid_t uid, const gid_t gid)
{
	int i;

	fprintf(stderr, "###'%s' ", path);
	for(i = 0; !END_NODE_HARDENING_WHITELIST(__hardening_node_whitelist[i]); ++i){
		if( MATCH(path, __hardening_node_whitelist[i].path) ){
			fprintf(stderr, " ok\n");
			return 1;
		}
	}
	fprintf(stderr, " nok\n");
	return 0;
}

#endif /* _UDEV_NODE_HARDENING_WHITELIST_ */
