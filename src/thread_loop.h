/* 
 * Copyright (C) 2012 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
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

/*
 * this enum show a thread state.
 * THREAD_LOOP : A thread is continued.
 * THREAD_END : A thread is finished.
 */
enum thread_s {
	THREAD_LOOP = 1,
	THREAD_END,
} thread_state;

/*
 * this store process_recv.
 */
void (*pthread_process_recv)(int);

/*
 * this function is implemented about a thread body.
 */
void pthread_loop(void);

/*
 * this function is called in pthread_loop, instead of process_connection.
 */
void pthread_process_connection(int ci);
