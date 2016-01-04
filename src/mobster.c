/* Copyright (C) 2012-2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 *
 * author Randy Caldejon <randy@packetchaser.org>
 *
 */

/* vim: noai:ts=4:sw=4 */

#define _GNU_SOURCE

#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "event_handlers.h"

uint64_t g_msgSubscribed = 0;
uint64_t g_msgReceived = 0;
uint64_t g_running = 1;

#define MOBSTER_ROOT    "MOBSTER_ROOT"

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */

int main(int argc, char **argv)
{
    struct stat sb;

    char* mobster_root;
    char* mobster_config;
    if ( argc > 2 ) /* Check to see if too many arguments were presented */
    {
        fprintf (stderr, "Too many arguments supplied\n");
        exit (EXIT_FAILURE);
    }
    else if ( argc == 2) /* Second Option is location of config file */
    {
        if ((lstat (argv[1],&sb)<0) || !S_ISREG(sb.st_mode))
        {
            mobster_root=getenv(MOBSTER_ROOT);
            char config_file [PATH_MAX];
            snprintf (config_file, PATH_MAX, "%s/%s", mobster_root, "/scripts/config.lua");

            if (!mobster_root)
            {
                fprintf (stderr,"Config file %s and environment variable MOBSTER_ROOT do not exist\n", argv[1]);
                exit (EXIT_FAILURE);
            }
            else if ((lstat (config_file,&sb)<0) || !S_ISREG(sb.st_mode))
            {
                fprintf (stderr,"Config file specified does not exist. $MOBSTER_ROOT/scripts/config.lua does not exist\n");
                exit (EXIT_FAILURE);
            }
            else
            {
                mobster_config=config_file;
            }
        }
        else
        {
            mobster_config=argv[1];
        }
    }
    else /* Otherwise look for mobster_root */
    {
        mobster_root=getenv(MOBSTER_ROOT);

        if (!mobster_root)
        {
            fprintf (stderr,"Must define environment variable MOBSTER_ROOT\n");
            exit (EXIT_FAILURE);
        }
        if ((lstat (mobster_root,&sb)<0) || !S_ISDIR(sb.st_mode))
        {
            fprintf (stderr,"MOBSTER_ROOT %s does not exist\n", mobster_root);
            exit (EXIT_FAILURE);
        }
        char config_file [PATH_MAX];
        snprintf (config_file, PATH_MAX, "%s/%s", mobster_root, "/scripts/config.lua");
        if ((lstat (config_file,&sb)<0) || !S_ISREG(sb.st_mode))
        {
            fprintf (stderr,"$MOBSTER_ROOT/scripts/config.lua does not exist\n.");
            exit (EXIT_FAILURE);
        }
        mobster_config=config_file;
    }
    int path_len = strlen(mobster_config);
    if (path_len > PATH_MAX)
    {
        fprintf (stderr,"Pathname of config file is too large (%i characters)", path_len);
        exit (EXIT_FAILURE);
    }

    signal(SIGPIPE, SIG_IGN);
    openlog ("mobster", LOG_PERROR, LOG_USER);

    pthread_setname_np(pthread_self(), "mobster");

    if (mobster_start (mobster_config) < 0)
    {
        syslog (LOG_ERR,"mobster_start() failed");
        return (EXIT_FAILURE);
    }
    while (g_running)
    {
        sleep(1);
    }
    closelog ();

    return (EXIT_SUCCESS);
}

/*
 * ---------------------------------------------------------------------------------------
 */

