/*
 * Copyright (C) 2016 Jan Pokorny <jpokorny@redhat.com>
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

#include <qb/qblog.h>

#include "b_config.h"

/* qb logging compat definitions */
#if (!defined LOGGING_LIBQB_MAJOR || (LOGGING_LIBQB_MAJOR < 1))
enum tmp_log_target_slot {
	TMP_LOG_SYSLOG = QB_LOG_SYSLOG,
	TMP_LOG_STDERR = QB_LOG_STDERR,
	TMP_LOG_BLACKBOX = QB_LOG_BLACKBOX,
	TMP_LOG_TARGET_MAX = QB_LOG_TARGET_MAX,
};

#undef QB_LOG_SYSLOG
#undef QB_LOG_STDERR
#undef QB_LOG_BLACKBOX
#undef QB_LOG_TARGET_MAX

enum qb_log_target_slot {
	QB_LOG_TARGET_START,
	QB_LOG_SYSLOG = TMP_LOG_SYSLOG,
	QB_LOG_STDERR = TMP_LOG_STDERR,
	QB_LOG_BLACKBOX = TMP_LOG_BLACKBOX,
	QB_LOG_TARGET_MAX = TMP_LOG_TARGET_MAX,
};

#define QB_LOG_CTL2_S(a)	(a)
#define qb_log_ctl2(t, s, a)	((void) 0)
#endif


#ifndef HA_LOG_FACILITY
/* based on glue/configure.ac of glue project: http://hg.linux-ha.org/glue */
#define HA_LOG_FACILITY	LOG_DAEMON
#endif

extern int debug_level;
#define ANYDEBUG	(debug_level)

void alt_qb_inherit_logging_environment(void);

#define cl_log_set_entity(ent) \
	(void) qb_log_ctl2(QB_LOG_SYSLOG, QB_LOG_CONF_IDENT, QB_LOG_CTL2_S(ent))

#define cl_log_enable_stderr(b) \
	(void) qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, b ? QB_TRUE : QB_FALSE)

#define cl_log_set_facility(f) \
	(void) qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_FACILITY, f)

#define cl_inherit_logging_environment(logqueuemax) \
	alt_qb_inherit_logging_environment()
