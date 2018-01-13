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
	va_list ap;

	va_start(ap, fmt);
	
	//return; // be silent

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;
		
		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		char *f;
		int len;
		time_t now;
		struct tm tm, *tm_p;

		time(&now);

		pthread_mutex_lock(&applog_lock);
		tm_p = localtime(&now);
		memcpy(&tm, tm_p, sizeof(tm));
		pthread_mutex_unlock(&applog_lock);

		len = 40 + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d] %s\n",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			fmt);
		pthread_mutex_lock(&applog_lock);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
		fflush(stderr);
		pthread_mutex_unlock(&applog_lock);
	}
	va_end(ap);
}



void diff_to_target(uint32_t *target, double diff)
{
	uint64_t m;
	int k;
	
	for (k = 6; k > 0 && diff > 1.0; k--)
		diff /= 4294967296.0;
	m = 4294901760.0 / diff;
	if (m == 0 && k == 6)
		memset(target, 0xff, 32);
	else {
		memset(target, 0, 32);
		target[k] = (uint32_t)m;
		target[k + 1] = (uint32_t)(m >> 32);
	}
}




void bin2hex(char *s, const unsigned char *p, size_t len)
{
	int i;
	for (i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02X", (unsigned int) p[i]);
}

char *abin2hex(const unsigned char *p, size_t len)
{
	char *s = malloc((len * 2) + 1);
	if (!s)
		return NULL;
	bin2hex(s, p, len);
	return s;
}

bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	char hex_byte[3];
	char *ep;

	hex_byte[2] = '\0';

	while (*hexstr && len) {
		if (!hexstr[1]) {
			applog(LOG_ERR, "hex2bin str truncated");
			return false;
		}
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		*p = (unsigned char) strtol(hex_byte, &ep, 16);
		if (*ep) {
			applog(LOG_ERR, "hex2bin failed on '%s'", hex_byte);
			return false;
		}
		p++;
		hexstr += 2;
		len--;
	}

	return(!len) ? true : false;
/*	return (len == 0 && *hexstr == 0) ? true : false; */
}



int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}




struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}

void tq_free(struct thread_q *tq)
{
	struct tq_ent *ent, *iter;

	if (!tq)
		return;

	list_for_each_entry_safe(ent, iter, &tq->q, q_node, struct tq_ent) {
		list_del(&ent->q_node);
		free(ent);
	}

	pthread_cond_destroy(&tq->cond);
	pthread_mutex_destroy(&tq->mutex);

	memset(tq, 0, sizeof(*tq));	/* poison */
	free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q *tq)
{
	tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q *tq, void *data)
{
	struct tq_ent *ent;
	bool rc = true;

	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->data = data;
	INIT_LIST_HEAD(&ent->q_node);

	pthread_mutex_lock(&tq->mutex);

	if (!tq->frozen) {
		list_add_tail(&ent->q_node, &tq->q);
	} else {
		free(ent);
		rc = false;
	}

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);

	return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
	struct tq_ent *ent;
	void *rval = NULL;
	int rc;

	pthread_mutex_lock(&tq->mutex);

	if (!list_empty(&tq->q))
		goto pop;

	if (abstime)
		rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
	else
		rc = pthread_cond_wait(&tq->cond, &tq->mutex);
	if (rc)
		goto out;
	if (list_empty(&tq->q))
		goto out;

pop:
	ent = list_entry(tq->q.next, struct tq_ent, q_node);
	rval = ent->data;

	list_del(&ent->q_node);
	free(ent);

out:
	pthread_mutex_unlock(&tq->mutex);
	return rval;
}
