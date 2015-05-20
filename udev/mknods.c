/*
 * Copyright (C) 2007-2009 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "udev.h"
#include "config.h"

static bool debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "%s: ", fn);
		vfprintf(stderr, format, args);
	} else {
		va_list args2;

		va_copy(args2, args);
		vfprintf(stderr, format, args2);
		va_end(args2);
		vsyslog(priority, format, args);
	}
}

static const struct udevadm_cmd *udevadm_cmds[] = {
	&udevadm_trigger,
	&udevadm_settle,
};

static int run_command(struct udev *udev, const struct udevadm_cmd *cmd, int argc, char *argv[])
{
	if (cmd->debug) {
		debug = true;
		if (udev_get_log_priority(udev) < LOG_INFO)
			udev_set_log_priority(udev, LOG_INFO);
	}
	info(udev, "calling: %s\n", cmd->name);
	return cmd->cmd(udev, argc, argv);
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	static const struct option options[] = {
#ifdef DEBUG
		{ "debug", no_argument, NULL, 'd' },
#endif
		{}
	};
	char *commandline, *command, *arguments;
	unsigned int i;
	int rc = 1;

	udev = udev_new();
	if (udev == NULL)
		goto out;

	udev_log_init("mknods");

#ifdef DEBUG
	udev_set_log_fn(udev, log_fn);
	for (;;) {
		int option;

		option = getopt_long(argc, argv, "+d", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			debug = true;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		default:
			goto out;
		}
	}
#endif

	info(udev, "runtime dir '%s'\n", udev_get_run_path(udev));
  for (i = 0; i < ARGUMENTS_SIZE; ++i) {
    rc |= run_command(udev, mknods_arguments[i].cmd, mknods_arguments[i].argc, (char **)mknods_arguments[i].argv);
  }

out:
	udev_unref(udev);
#ifdef DEBUG
	udev_log_close();
#endif
	return rc;
}