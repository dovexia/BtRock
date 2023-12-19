/**
 * @copyright Copyright (c) 2023, ThunderSoft, Ltd.
 * @file lehcicmdtest.h
 * @author  xiachen0629@thundersoft.com
 * @brief
 * @date 2023-11-25
 *
 * @par History:
 * <table>
 * <tr><th>Date         <th>version <th>Author       <th>Description
 * <tr><td>2023-11-25   <td>1.0     <td>xiachen0629  <td>init version
 * </table>
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <wordexp.h>
#include <glib.h>

#include "src/shared/shell.h"

void cmd_lehcicmd_getleaddr(int argc, char *argv[]);

extern const struct bt_shell_menu lehcicmd_menu;