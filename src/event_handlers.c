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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>

#include <hiredis/hiredis.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#ifdef ENABLE_JIT
#include <luajit-2.0/luajit.h>
#endif

static char *g_redis_host = "127.0.0.1";
static char *script_dir = "/opt/mobster/scripts";
static char *notice_key = "EVE:notice";
static char *log_dir = "/var/log/mobster";
static char *log_file = "mobster.log";
static int g_redis_port = 6379;

static int g_verbose = 0;
static redisContext *g_redis_ctx = NULL;
static pthread_mutex_t g_redis_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_fp = NULL;
extern uint64_t g_running;

#define MOBSTER_ROOT    "MOBSTER_ROOT"

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
void file_rotate(int signo)
{
    if (signo == SIGUSR1)
    {
        char newfile [PATH_MAX];

        pthread_mutex_lock(&g_redis_mutex);
        fclose (g_fp);

        char filename [PATH_MAX];
        snprintf(filename, PATH_MAX, "%s/%s", log_dir, log_file);
        g_fp = fopen (filename, "w+");
        if (!g_fp)
        {
            perror ("fopen");
            pthread_mutex_unlock(&g_redis_mutex);
            abort ();
        }
        setvbuf(g_fp, NULL, _IOLBF, 0);

        pthread_mutex_unlock(&g_redis_mutex);
        syslog (LOG_ERR,"%s: received HUP to truncate %s/%s", log_dir, log_file);
    }
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void *notice_thread (void *v)
{
    (void) v;

    if (signal(SIGUSR1, file_rotate) == SIG_ERR)
    {
        syslog (LOG_ERR,"signal() failed; %s", strerror (errno));
        abort ();
    }

    if (mkdir(log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0)
    {
        if (errno != EEXIST)
        {
            syslog (LOG_ERR,"mkdir %s; %s", log_dir, strerror (errno));
            abort ();
        }
    }

    char filename [PATH_MAX];
    snprintf(filename, PATH_MAX, "%s/%s", log_dir, log_file);
    g_fp = fopen (filename, "a+");
    if (!g_fp)
    {
        perror ("fopen");
        abort ();
    }
    setvbuf(g_fp, NULL, _IOLBF, 0);

    redisContext *redis_ctx = redisConnect(g_redis_host, g_redis_port);
    if (redis_ctx != NULL && redis_ctx->err)
    {
        syslog (LOG_ERR,"redisConnect() failed; %s", redis_ctx->errstr);
        abort ();
    }

    redisReply *reply = redisCommand(redis_ctx,"SUBSCRIBE %s", notice_key);

    if (reply->type==REDIS_REPLY_ERROR)
    {
        syslog (LOG_ERR,"redisCommand() failed; %s", reply->str);
        abort ();
    }
    if (reply) freeReplyObject(reply);

    syslog (LOG_INFO,"Notice thread running");
    while(redisGetReply(redis_ctx,(void **) &reply) == REDIS_OK)
    {
        if (reply->type==REDIS_REPLY_ARRAY && reply->elements>2)
        {
            pthread_mutex_lock(&g_redis_mutex);
            fputs (reply->element[2]->str, g_fp);
            fputs ("\n", g_fp);
            pthread_mutex_unlock(&g_redis_mutex);
            if (g_verbose) puts (reply->element[2]->str);
        }
        if (reply) freeReplyObject(reply);
    }
    fclose (g_fp);
    redisFree (redis_ctx);
    pthread_exit(NULL);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static int mobster_notify(lua_State *L)
{
    const char *timestamp = luaL_checkstring(L, 1);
    const char *category = luaL_checkstring(L, 2);
    const char *action = luaL_checkstring(L, 3);
    const char *message = luaL_checkstring(L, 4);

    char json [1024];
    memset (json, 0, sizeof(json));
    snprintf (json,
            sizeof(json)-1,
            "{\"timestamp\":\"%s\",\"event_type\":\"notice\",\"notice\":{\"category\":\"%s\",\"action\":\"%s\",\"message\":\"%s\"}}",
            timestamp, category, action, message);
    if (g_verbose) fprintf (stderr,"%s: %s\n", __FUNCTION__, json);

    redisReply *reply = redisCommand(g_redis_ctx,"PUBLISH %s %s", notice_key, json);

    if (reply)
    {
        freeReplyObject(reply);
    }
    else
    {
        syslog (LOG_ERR,"PUBLISH - %s", g_redis_ctx->errstr);
    }
    return 0;
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void *lua_thread (void *ptr)
{
    char *name = NULL;
    const char* lua_script = strndup((const char *)ptr, PATH_MAX);

    pthread_detach(pthread_self());
    /*
     * Set thread name to the file name of the lua script
     */
    const char *path = strndup (lua_script, PATH_MAX);
    char *period = strrchr (path, (int)'.');
    if (period) *period = '\0';
    char* slash = strrchr (path, (int)'/');
    if (slash) name = (slash+1);
    if (name)
    {
        pthread_setname_np(pthread_self(), name);
    }

    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    syslog (LOG_INFO, "Loading %s", lua_script);
    lua_pushstring(L, script_dir);
    lua_setglobal(L, "script_dir");
    lua_pushstring(L, log_dir);
    lua_setglobal(L, "log_dir");

    if (luaL_loadfile(L, lua_script)||lua_pcall(L, 0, 0, 0))
    {
        syslog (LOG_ERR, "luaL_loadfile %s failed - %s",lua_script, lua_tostring(L, -1));
        pthread_exit(NULL);
    }

    /* globally set redis host and port number in the LUA engine */
    lua_pushnumber(L, g_redis_port);
    lua_setglobal(L, "redis_port");
    lua_pushstring(L, g_redis_host);
    lua_setglobal(L, "redis_host");
    lua_pushcfunction(L, mobster_notify);
    lua_setglobal(L, "mobster_notify");
    lua_pushstring(L, notice_key);
    lua_setglobal(L, "notice_key");


    syslog (LOG_NOTICE,"Running %s as %s\n", lua_script, name);
    lua_getglobal(L, "run");
    if (lua_pcall(L, 0, 0, 0))
    {
        syslog (LOG_ERR,"lua_pcall run(%s) failed; %s",lua_script, lua_tostring(L, -1));
        pthread_exit(NULL);
    }
    lua_close(L);
    syslog (LOG_NOTICE,"%s exiting", (name?name:"thread"));
    pthread_exit(NULL);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */

static void run_mobster (const char* mobster_config)
{
    struct stat sb;

    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    if (luaL_loadfile(L, mobster_config)) 
    {
        syslog (LOG_ERR,"luaL_loadfile failed; %s",lua_tostring(L, -1));
        abort ();
    }

    if (lua_pcall(L, 0, 0, 0))
    {
        syslog (LOG_ERR,"lua_pcall failed; %s",lua_tostring(L, -1));
        abort ();
    }

    lua_getglobal(L, "redis_host");
    if (lua_isstring(L, -1))
    {
        g_redis_host = strdup(lua_tostring(L, -1));
    }

    lua_getglobal(L, "redis_port");
    if (lua_isnumber(L, -1))
    {
        g_redis_port = (int) lua_tonumber(L, -1);
    }

    /* Added the following options below to allow customization of running instances */
    lua_getglobal(L, "notice_key");
    if (lua_isstring(L, -1))
    {
        notice_key = strdup(lua_tostring(L, -1));
    }

    lua_getglobal(L, "script_dir");

    if (lua_isstring(L, -1))
    {
        script_dir = strdup(lua_tostring(L, -1));
    }

    if ((lstat (script_dir,&sb)<0) || !S_ISDIR(sb.st_mode))
    {
        char* mobster_root=getenv(MOBSTER_ROOT);
        char temp_script_dir [PATH_MAX];

        snprintf (temp_script_dir, PATH_MAX, "%s/%s", mobster_root, "/scripts");

        if (!temp_script_dir || !mobster_root)
        {
            fprintf (stderr,"Script Directory %s does not exist and cannot location under mobster_root\n", script_dir);
            exit (EXIT_FAILURE);
        }
        else
        {
            fprintf(stderr,"Script Directory %s does not exist.  Using Script directory under mobster_root\n", script_dir);
            script_dir=temp_script_dir;
        }
    }

    lua_getglobal(L, "log_dir");
    if (lua_isstring(L, -1))
    {
        log_dir = strdup(lua_tostring(L, -1));
    }

    lua_getglobal(L, "log_file");
    if (lua_isstring(L, -1))
    {
        log_file = strdup(lua_tostring(L, -1));
    }
    /* End of new keys added */

    lua_getglobal(L, "mobster_scripts");

    lua_pushnil(L);

    if (!lua_istable(L, -2))
    {
        syslog (LOG_ERR,"Configuration item mobster_scripts must be a table");
        pthread_exit(NULL);
    }

    g_redis_ctx = redisConnect(g_redis_host, g_redis_port);
    if (g_redis_ctx != NULL && g_redis_ctx->err)
    {
        syslog (LOG_ERR,"redisConnect() failed; %s", g_redis_ctx->errstr);
        abort ();
    }

    pthread_t thread;
    if(pthread_create(&thread, NULL, notice_thread, (void *) NULL)!=0)
    {
        syslog (LOG_ERR,"pthread_create() %s", strerror (errno));
        pthread_exit(NULL);
    }

    while (lua_next(L, -2))
    {
        struct stat sb;
        const char *lua_script = lua_tostring(L, -1);
        char tmp [PATH_MAX];
        snprintf (tmp, PATH_MAX, "%s/%s", script_dir, lua_script);

        /*
         * check that file exists with execute permissions
         */
        if ((lstat (tmp,&sb)>=0) && S_ISREG(sb.st_mode))
        {
            char *mobster_script = strndup((const char *)tmp, PATH_MAX);
            if(pthread_create(&thread, NULL, lua_thread, (void *) mobster_script)!=0)
            {
                syslog (LOG_ERR,"pthread_create() %s", strerror (errno));
                pthread_exit(NULL);
            }
        }
        else
        {
            syslog (LOG_ERR,"Mobster script %s does not exist.", lua_script);
        }
        lua_pop(L,1);
    }
    lua_close(L);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */

void mobster_start(const char* mobster_config)
{
    g_verbose=isatty(1);
    run_mobster (mobster_config);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */

#ifdef UNIT_TEST
int main(void)
{
    openlog ("mobster", LOG_PERROR, LOG_USER);
    mobster_start("mobster-config.lua");
    closelog();
}
#endif

/*
 * ---------------------------------------------------------------------------------------
 */

