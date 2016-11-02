#ifndef _UDEV_RULES_HARDENING_WHITELIST_
#define _UDEV_RULES_HARDENING_WHITELIST_

#include "udev-hardening-utils.h"

static int ACCEPTED_RULE(char *i, char **w, int(*m)(char *, char *))
{
	return 1; char **j;
	FOREACH(j, w)
		if (m(*j, i)) return 1;
	return 0;
}

int match(char *a, char *b) { return MATCH(a, b); }

#ifndef ACCEPTED_IMPORT_PROG
# define ACCEPTED_IMPORT_PROG(i) ACCEPTED_RULE(i, \
			__hardening_import_prog_whitelist, \
			match)
#endif

#ifndef ACCEPTED_RUN
# define ACCEPTED_RUN(i) ACCEPTED_RULE(i, \
			__hardening_run_whitelist, \
			match)
#endif

#ifndef ACCEPTED_IMPORT_BUILTIN
# define ACCEPTED_IMPORT_BUILTIN(i) ACCEPTED_RULE(i, \
			__hardening_import_builtin_whitelist, \
			match)
#endif

static const char * __hardening_import_builtin_whitelist[] = {
	"input_id",
	"path_id",
	"usb_id",
	NULL
};

static const char * __hardening_run_whitelist[] = {
	NULL
};

static const char * __hardening_import_prog_whitelist[] = {
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:0",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:10",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:11",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:12",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:13",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:14",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:15",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:16",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:24",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:4",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:48",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:5",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:6",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:7",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:72",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:8",
	"/sbin/blkid -o udev -p /dev/.tmp-block-179:9",
	"/sbin/blkid -o udev -p /dev/.tmp-block-7:1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-7:2",
	"/sbin/blkid -o udev -p /dev/.tmp-block-7:3",
	"/sbin/blkid -o udev -p /dev/.tmp-block-7:4",
	"/sbin/blkid -o udev -p /dev/.tmp-block-7:5",
	"/sbin/blkid -o udev -p /dev/.tmp-block-7:6",
	"/sbin/blkid -o udev -p /dev/.tmp-block-7:7",
	"/sbin/blkid -o udev -p /dev/loop0",
	"/sbin/blkid -o udev -p /dev/mmcblk0p10",
	"/sbin/blkid -o udev -p /dev/mmcblk0p11",
	"/sbin/blkid -o udev -p /dev/mmcblk0p12",
	"/sbin/blkid -o udev -p /dev/mmcblk0p13",
	"/sbin/blkid -o udev -p /dev/mmcblk0p14",
	"/sbin/blkid -o udev -p /dev/mmcblk0p15",
	"/sbin/blkid -o udev -p /dev/mmcblk0p16",
	"/sbin/blkid -o udev -p /dev/mmcblk0p8",
	"/sbin/blkid -o udev -p /dev/mmcblk0p9",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:1",
	"/sbin/blkid -o udev -p /dev/sda1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:17",
	"/sbin/blkid -o udev -p /dev/sdb1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:33",
	"/sbin/blkid -o udev -p /dev/sdc1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:49",
	"/sbin/blkid -o udev -p /dev/sdd1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:65",
	"/sbin/blkid -o udev -p /dev/sde1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:81",
	"/sbin/blkid -o udev -p /dev/sdf1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:97",
	"/sbin/blkid -o udev -p /dev/sdg1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:113",
	"/sbin/blkid -o udev -p /dev/sdh1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:129",
	"/sbin/blkid -o udev -p /dev/sdi1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:145",
	"/sbin/blkid -o udev -p /dev/sdj1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:161",
	"/sbin/blkid -o udev -p /dev/sdk1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:177",
	"/sbin/blkid -o udev -p /dev/sdl1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:193",
	"/sbin/blkid -o udev -p /dev/sdm1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:209",
	"/sbin/blkid -o udev -p /dev/sdn1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:225",
	"/sbin/blkid -o udev -p /dev/sdo1",
	"/sbin/blkid -o udev -p /dev/.tmp-block-8:241",
	"/sbin/blkid -o udev -p /dev/sdp1",
	"mtd_probe /dev/.tmp-char-90:1",
	"pci-db /devices/soc0/soc.5/9b00000.pcie/pci0000:00/0000:00:01.0/net/ra0",
	"v4l_id /dev/.tmp-char-81:0",
	"v4l_id /dev/.tmp-char-81:1",
	"v4l_id /dev/.tmp-char-81:10",
	"v4l_id /dev/.tmp-char-81:11",
	"v4l_id /dev/.tmp-char-81:12",
	"v4l_id /dev/.tmp-char-81:13",
	"v4l_id /dev/.tmp-char-81:14",
	"v4l_id /dev/.tmp-char-81:15",
	"v4l_id /dev/.tmp-char-81:16",
	"v4l_id /dev/.tmp-char-81:17",
	"v4l_id /dev/.tmp-char-81:18",
	"v4l_id /dev/.tmp-char-81:19",
	"v4l_id /dev/.tmp-char-81:2",
	"v4l_id /dev/.tmp-char-81:20",
	"v4l_id /dev/.tmp-char-81:21",
	"v4l_id /dev/.tmp-char-81:22",
	"v4l_id /dev/.tmp-char-81:23",
	"v4l_id /dev/.tmp-char-81:24",
	"v4l_id /dev/.tmp-char-81:25",
	"v4l_id /dev/.tmp-char-81:26",
	"v4l_id /dev/.tmp-char-81:3",
	"v4l_id /dev/.tmp-char-81:4",
	"v4l_id /dev/.tmp-char-81:5",
	"v4l_id /dev/.tmp-char-81:6",
	"v4l_id /dev/.tmp-char-81:7",
	"v4l_id /dev/.tmp-char-81:8",
	"v4l_id /dev/.tmp-char-81:9",
	NULL
};

#endif /* _UDEV_RULES_HARDENING_WHITELIST_ */
