#ifndef __MKNODS_CONFIG__
#define __MKNODS_CONFIG__

/**
 * Sample configuration for mknods, a statically configured udevadm.
 *
 * In this file, you can configure mknods behavior, which commands will
 * it run when you execute mknods.
 *
 */

#include "udev.h"

/**
 * Command structure containing udevadm_cmd, argc and argv to execute
 */
struct mknods_arg {
  const struct udevadm_cmd *cmd;
  const int    argc;
  const char **argv;
};

/**
 * External definitions of udevadm commands you need
 */
extern const struct udevadm_cmd udevadm_trigger;
extern const struct udevadm_cmd udevadm_settle;

/**
 * How many commands you want to execute
 */
#define ARGUMENTS_SIZE 3

/**
 * Which commands you want to execute
 */
static const struct mknods_arg mknods_arguments[ARGUMENTS_SIZE] = {
  (const struct mknods_arg){ &udevadm_trigger, 2, (const char *[]){"--action=add", "--type=subsystems", NULL} },
  (const struct mknods_arg){ &udevadm_trigger, 2, (const char *[]){"--action=add", "--type=devices", NULL} },
  (const struct mknods_arg){ &udevadm_settle,  1, (const char *[]){"--timeout=60", NULL} }
};

#endif
