/* 
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

#ifndef _LOG_H
#define _LOG_H

#include <syslog.h>

void log_level(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

int setup_logging(void);
void close_logging(void);

#define log_debug(fmt, args...)		log_level(LOG_DEBUG, fmt, ##args)
#define log_info(fmt, args...)		log_level(LOG_INFO, fmt, ##args)
#define log_error(fmt, args...)		log_level(LOG_ERR, fmt, ##args)

#endif /* _LOG_H */
