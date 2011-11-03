/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 * (This code is borrowed from the sanlock project which is hosted on 
 * fedorahosted.org.)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>

#include "booth.h"
#include "log.h"

#define LOG_STR_LEN		256
static char log_str[LOG_STR_LEN];

static pthread_t thread_handle;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t log_cond = PTHREAD_COND_INITIALIZER;

static char log_dump[BOOTH_LOG_DUMP_SIZE];
static unsigned int log_point;
static unsigned int log_wrap;

static char logfile_path[PATH_MAX];
static FILE *logfile_fp;

struct entry {
	int level;
	char str[LOG_STR_LEN];
};

#define BOOTH_LOG_DEFAULT_ENTRIES		4096
static struct entry *log_ents;
static unsigned int log_num_ents = BOOTH_LOG_DEFAULT_ENTRIES;
static unsigned int log_head_ent; /* add at head */
static unsigned int log_tail_ent; /* remove from tail */
static unsigned int log_dropped;
static unsigned int log_pending_ents;
static unsigned int log_thread_done;

extern int log_logfile_priority;
extern int log_syslog_priority;
extern int log_stderr_priority;

static void _log_save_dump(int level __attribute__((unused)), int len)
{
	int i;

	for (i = 0; i < len; i++) {
		log_dump[log_point++] = log_str[i];

		if (log_point == BOOTH_LOG_DUMP_SIZE) {
			log_point = 0;
			log_wrap = 1;
		}
	}
}

static void _log_save_ent(int level, int len)
{
	struct entry *e;

	if (!log_ents)
		return;

	if (log_pending_ents == log_num_ents) {
		log_dropped++;
		return;
	}

	e = &log_ents[log_head_ent++];
	log_head_ent = log_head_ent % log_num_ents;
	log_pending_ents++;

	e->level = level;
	memcpy(e->str, log_str, len);
}

void log_level(int level, const char *fmt, ...)
{
	va_list ap;
	char name[BOOTH_NAME_LEN + 1];
	int ret, pos = 0;
	int len = LOG_STR_LEN - 2; /* leave room for \n\0 */

	memset(name, 0, sizeof(name));

	pthread_mutex_lock(&log_mutex);

	ret = snprintf(log_str + pos, len - pos, "%ld %s ",
		       time(NULL), name);
	pos += ret;

	va_start(ap, fmt);
	ret = vsnprintf(log_str + pos, len - pos, fmt, ap);
	va_end(ap);

	if (ret >= len - pos)
		pos = len - 1;
	else
		pos += ret;

	log_str[pos++] = '\n';
	log_str[pos++] = '\0';

	/*
	 * save all messages in circular buffer "log_dump" that can be
	 * sent over unix socket
	 */

	_log_save_dump(level, pos - 1);

	/*
	 * save some messages in circular array "log_ents" that a thread
	 * writes to logfile/syslog
	 */

	if (level <= log_logfile_priority || level <= log_syslog_priority)
		_log_save_ent(level, pos);

	if (level <= log_stderr_priority)
		fprintf(stderr, "%s", log_str);

	pthread_cond_signal(&log_cond);
	pthread_mutex_unlock(&log_mutex);
}

static void write_entry(int level, char *str)
{
        if ((level <= log_logfile_priority) && logfile_fp) {
                fprintf(logfile_fp, "%s", str);
                fflush(logfile_fp);
        }
        if (level <= log_syslog_priority)
                syslog(level, "%s", str);
}

static void write_dropped(int level, int num)
{
	char str[LOG_STR_LEN];
	sprintf(str, "dropped %d entries", num);
	write_entry(level, str);
}

static void *log_thread_fn(void *arg __attribute__((unused)))
{
	char str[LOG_STR_LEN];
	struct entry *e;
	int level, prev_dropped = 0;

	while (1) {
		pthread_mutex_lock(&log_mutex);
		while (log_head_ent == log_tail_ent) {
			if (log_thread_done) {
				pthread_mutex_unlock(&log_mutex);
				goto out;
			}
			pthread_cond_wait(&log_cond, &log_mutex);
		}

		e = &log_ents[log_tail_ent++];
		log_tail_ent = log_tail_ent % log_num_ents;
		log_pending_ents--;

		memcpy(str, e->str, LOG_STR_LEN);
		level = e->level;

		prev_dropped = log_dropped;
		log_dropped = 0;
		pthread_mutex_unlock(&log_mutex);

		if (prev_dropped) {
			write_dropped(level, prev_dropped);
			prev_dropped = 0;
		}

		write_entry(level, str);
	}
out:
	pthread_exit(NULL);
}


int setup_logging(void)
{
	int fd, rv;

	snprintf(logfile_path, PATH_MAX, "%s/%s", BOOTH_LOG_DIR,
		BOOTH_LOGFILE_NAME);

	logfile_fp = fopen(logfile_path, "a+");
	if (logfile_fp) {
		fd = fileno(logfile_fp);
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
	}

	log_ents = malloc(log_num_ents * sizeof(struct entry));
	if (!log_ents) {
		fclose(logfile_fp);
		logfile_fp = NULL;
		return -1;
        }
	memset(log_ents, 0, log_num_ents * sizeof(struct entry));

	openlog(DAEMON_NAME, LOG_CONS | LOG_PID, LOG_DAEMON);

	rv = pthread_create(&thread_handle, NULL, log_thread_fn, NULL);
	if (rv)
		return -1;

	return 0;
}

void close_logging(void)
{
	pthread_mutex_lock(&log_mutex);
	log_thread_done = 1;
	pthread_cond_signal(&log_cond);
	pthread_mutex_unlock(&log_mutex);
	pthread_join(thread_handle, NULL);

	pthread_mutex_lock(&log_mutex);
	closelog();
	if (logfile_fp) {
		fclose(logfile_fp);
		logfile_fp = NULL;
	}
	pthread_mutex_unlock(&log_mutex);
}
