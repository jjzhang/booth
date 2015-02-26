/*
 * Copyright (C) 2014 Dejan Muhamedagic <dejan@suse.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _TIMER_H
#define _TIMER_H

#include <time.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>

#if _POSIX_TIMERS > 0

#if defined(CLOCK_MONOTONIC)
#	define BOOTH_CLOCK CLOCK_MONOTONIC
#else
#	define BOOTH_CLOCK CLOCK_REALTIME
#endif

#define NSECS 1000000000L /* nanoseconds */
#define TIME_FAC (NSECS/TIME_RES)
#define SUBSEC tv_nsec

typedef struct timespec timetype;

#define get_time(p) clock_gettime(BOOTH_CLOCK, p)

#define time_cmp(a, b, CMP)           \
  (((a)->tv_sec == (b)->tv_sec) ?     \
   ((a)->tv_nsec CMP (b)->tv_nsec) :  \
   ((a)->tv_sec CMP (b)->tv_sec))

void time_sub(struct timespec *a, struct timespec *b, struct timespec *res);
void time_add(struct timespec *a, struct timespec *b, struct timespec *res);
time_t get_secs(struct timespec *p);
time_t wall_ts(time_t t);
time_t unwall_ts(time_t t);

#else

#define MUSECS 1000000L /* microseconds */
#define TIME_FAC (MUSECS/TIME_RES)
#define SUBSEC tv_usec

typedef struct timeval timetype;
#define get_time(p) gettimeofday(p, NULL)
#define time_sub timersub
#define time_add timeradd
#define time_cmp timercmp
#define get_secs time

#define wall_ts(t) (t)
#define unwall_ts(t) (t)

#endif

int is_past(timetype *p);
void secs2tv(time_t secs, timetype *p);
void time_reset(timetype *p);
int time_sub_int(timetype *a, timetype *b);
void set_future_time(timetype *a, int b);
int time_left(timetype *p);
void copy_time(timetype *src, timetype *dst);
void interval_add(timetype *p, int interval, timetype *res);
int is_time_set(timetype *p);
#define intfmt(t) "%d.%03d", (t)/TIME_RES, (t)%TIME_RES

/* random time from 0 to t ms (1/TIME_RES) */
#define rand_time(t) cl_rand_from_interval(0, t*(TIME_RES/1000))

#endif
