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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "timer.h"

void time_sub(struct timespec *a, struct timespec *b, struct timespec *res)
{
	if (a->tv_nsec < b->tv_nsec) {
		res->tv_sec = a->tv_sec - b->tv_sec - 1;
		res->tv_nsec = a->tv_nsec + (1000000000 - b->tv_nsec);
	} else {
		res->tv_sec = a->tv_sec - b->tv_sec;
		res->tv_nsec = a->tv_nsec - b->tv_nsec;
	}
}


void time_add(struct timespec *a, struct timespec *b, struct timespec *res)
{
	res->tv_nsec = (a->tv_nsec + b->tv_nsec) % 1000000000;
	res->tv_sec = a->tv_sec + b->tv_sec + ((a->tv_nsec + b->tv_nsec) / 1000000000);
}

time_t get_secs(time_t *p)
{
	struct timespec tv;
	time_t secs;

	get_time(&tv);
	secs = tv.tv_sec;
	if (p)
		*p = secs;
	return secs;
}

/* time booth_clk_t is a time since boot or similar, return
 * something humans can understand */
time_t wall_ts(time_t booth_clk_t)
{
	struct timespec booth_clk_now, now_tv, res;
	struct timeval now;

	get_time(&booth_clk_now);
	gettimeofday(&now, NULL);
	TIMEVAL_TO_TIMESPEC(&now, &now_tv);
	time_sub(&now_tv, &booth_clk_now, &res);
	return booth_clk_t + res.tv_sec;
}

/* time t is wall clock time, convert to time compatible
 * with our clock_gettime clock */
time_t unwall_ts(time_t t)
{
	struct timespec booth_clk_now, now_tv, res;
	struct timeval now;

	get_time(&booth_clk_now);
	gettimeofday(&now, NULL);
	TIMEVAL_TO_TIMESPEC(&now, &now_tv);
	time_sub(&now_tv, &booth_clk_now, &res);
	return t - res.tv_sec;
}
