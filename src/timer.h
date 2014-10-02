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
#include <sys/time.h>

#if _POSIX_TIMERS > 0

#if defined(CLOCK_MONOTONIC)
#	define BOOTH_CLOCK CLOCK_MONOTONIC
#else
#	define BOOTH_CLOCK CLOCK_REALTIME
#endif

typedef struct timespec timetype;

#define get_time(p) clock_gettime(BOOTH_CLOCK, p)

#define time_cmp(a, b, CMP)           \
  (((a)->tv_sec == (b)->tv_sec) ?     \
   ((a)->tv_nsec CMP (b)->tv_nsec) :  \
   ((a)->tv_sec CMP (b)->tv_sec))

void time_sub(struct timespec *a, struct timespec *b, struct timespec *res);
void time_add(struct timespec *a, struct timespec *b, struct timespec *res);
time_t get_secs(time_t *p);
time_t wall_ts(time_t t);
time_t unwall_ts(time_t t);

#define msecs(tv) ((tv).tv_nsec/1000000)

/* random time from 0 to t milliseconds */
#define rand_time_ms(tv, t) do { \
	tv.tv_sec = 0; \
	tv.tv_nsec = t * cl_rand_from_interval(0, 1000000); \
	} while(0)

#else

typedef struct timeval timetype;
#define get_time(p) gettimeofday(p, NULL)
#define time_sub timersub
#define time_add timeradd
#define time_cmp timercmp
#define get_secs time

#define msecs(tv) ((tv).tv_usec/1000)

/* random time from 0 to t milliseconds */
#define rand_time_ms(tv, t) do { \
	tv.tv_sec = 0; \
	tv.tv_usec = t * cl_rand_from_interval(0, 1000); \
	} while(0)

#define wall_ts(t) (t)
#define unwall_ts(t) (t)

#endif

#endif
