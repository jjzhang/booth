/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 * (This code is borrowed from the sanlock project which is hosted on 
 * fedorahosted.org.)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LOG_H
#define _LOG_H

#include "b_config.h"

#ifndef LOGGING_LIBQB
#include <heartbeat/glue_config.h>
#include <clplumbing/cl_log.h>
#define priv_log(prio, ...)		cl_log(prio, __VA_ARGS__)
#else
#include "alt/logging_libqb.h"
#define priv_log(prio, ...)		qb_log(prio, __VA_ARGS__)
#endif

#include "inline-fn.h"


#define log_debug(fmt, args...)		do { \
	if (ANYDEBUG) priv_log(LOG_DEBUG, fmt, ##args); } \
	while (0)
#define log_info(fmt, args...)		priv_log(LOG_INFO, fmt, ##args)
#define log_warn(fmt, args...)		priv_log(LOG_WARNING, fmt, ##args)
#define log_error(fmt, args...)		priv_log(LOG_ERR, fmt, ##args)

/* all tk_* macros prepend "%(tk->name): " (the caller needs to
 * have the ticket named tk!)
 */
#define tk_cl_log(sev, fmt, args...) \
	priv_log(sev, "%s (%s/%d/%d): " fmt, \
	tk->name, state_to_string(tk->state), tk->current_term, term_time_left(tk), \
	##args)
#define tk_cl_log_src(sev, fmt, args...) \
	priv_log(sev, "%s:%d: %s (%s/%d/%d): " fmt, \
	__FUNCTION__, __LINE__, \
	tk->name, state_to_string(tk->state), tk->current_term, term_time_left(tk), \
	##args)

#define tk_log_debug(fmt, args...)		do { \
	if (ANYDEBUG) tk_cl_log_src(LOG_DEBUG, fmt, ##args); } \
	while (0)
#define tk_log_info(fmt, args...)		tk_cl_log(LOG_INFO, fmt, ##args)
#define tk_log_warn(fmt, args...)		tk_cl_log(LOG_WARNING, fmt, ##args)
#define tk_log_error(fmt, args...)		tk_cl_log(LOG_ERR, fmt, ##args)

#endif /* _LOG_H */
