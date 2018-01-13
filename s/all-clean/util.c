/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2014 pooler
 * Copyright 2014-2015 John Doering <ghostlander@phoenixcoin.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE
#include "cpuminer-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <jansson.h>
#include <curl/curl.h>
#include <time.h>
#if defined(WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
#include "compat.h"
#include "miner.h"
#include "elist.h"

struct data_buffer {
	void		*buf;
	size_t		len;
};

struct upload_buffer {
	const void	*buf;
	size_t		len;
	size_t		pos;
};

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
};

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

void applog(int prio, const char *fmt, ...)
{
	
}


bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	
}
