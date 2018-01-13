/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014-2016 John Doering <ghostlander@phoenixcoin.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif
#include <jansson.h>
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"
#include "version.h"

#include "neoscrypt.h"



#define PROGRAM_NAME		"minerd"
#define LP_SCANTIME		60

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void)
{

}

static inline void affine_to_cpu(int id, int cpu)
{

}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{

}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif
		
enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
};

enum algos {
	ALGO_NEOSCRYPT,		/* NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20 */
	ALGO_ALTSCRYPT,		/* Scrypt(1024, 1, 1) with Salsa20/8 through NeoScrypt */
	ALGO_SCRYPT,		/* Scrypt(1024, 1, 1) with Salsa20/8 */
	ALGO_SHA256D,		/* SHA-256d */
};

static const char *algo_names[] = {

};

bool opt_debug = false;
bool opt_protocol = false;
static bool opt_benchmark = false;
bool opt_redirect = true;
bool want_longpoll = true;
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool want_stratum = true;
bool have_stratum = false;
bool use_syslog = false;
static bool opt_background = false;
static bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 30;
int opt_timeout = 0;
static int opt_scantime = 5;
static const bool opt_time = true;
static enum algos opt_algo = ALGO_NEOSCRYPT;
static uint opt_neoscrypt_profile = 0;
static uint opt_neoscrypt_asm = 0;
static uint opt_nfactor = 6;
static int opt_n_threads;
static int num_processors;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
static int pk_script_size;
static unsigned char pk_script[25];
static char coinbase_sig[101] = "";
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
struct work_restart *work_restart = NULL;
static struct stratum_ctx stratum;

pthread_mutex_t applog_lock;
static pthread_mutex_t stats_lock;

static unsigned long accepted_count = 0L;
static unsigned long rejected_count = 0L;
static double *thr_hashrates;

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};
#endif

#include "main.h"

static char const usage[] = "";




struct work {
	uint32_t data[32];
	uint32_t target[8];

	int height;
	char *txs;
	char *workid;

	char *job_id;
	size_t xnonce2_len;
	unsigned char *xnonce2;
};

static struct work g_work;
static time_t g_work_time;
static pthread_mutex_t g_work_lock;
static bool submit_old = false;
static char *lp_id;

static inline void work_free(struct work *w)
{
	//free(w->txs);
	//free(w->workid);
	//free(w->job_id);
	//free(w->xnonce2);
}

static inline void work_copy(struct work *dest, const struct work *src)
{
	
}

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	
}

static bool work_decode(const json_t *val, struct work *work) {
    
}

static bool gbt_work_decode(const json_t *val, struct work *work)
{
	#if 0
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevhash[8];
	uint32_t target[8];
	int cbtx_size;
	unsigned char *cbtx = NULL;
	int tx_count, tx_size;
	unsigned char txc_vi[9];
	unsigned char (*merkle_tree)[32] = NULL;
	bool coinbase_append = false;
	bool submit_coinbase = false;
	bool version_force = false;
	bool version_reduce = false;
	json_t *tmp, *txa;
	bool rc = false;

	tmp = json_object_get(val, "mutable");
	if (tmp && json_is_array(tmp)) {
		n = json_array_size(tmp);
		for (i = 0; i < n; i++) {
			const char *s = json_string_value(json_array_get(tmp, i));
			if (!s)
				continue;
			if (!strcmp(s, "coinbase/append"))
				coinbase_append = true;
			else if (!strcmp(s, "submit/coinbase"))
				submit_coinbase = true;
			else if (!strcmp(s, "version/force"))
				version_force = true;
			else if (!strcmp(s, "version/reduce"))
				version_reduce = true;
		}
	}

	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = json_integer_value(tmp);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = json_integer_value(tmp);
	if (version > 2) {
		if (version_reduce) {
			version = 2;
		} else if (!version_force) {
			applog(LOG_ERR, "Unrecognized block version: %u", version);
			goto out;
		}
	}

	if (unlikely(!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash)))) {
		applog(LOG_ERR, "JSON invalid previousblockhash");
		goto out;
	}

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = json_integer_value(tmp);

	if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}

	/* find count and size of transactions */
	txa = json_object_get(val, "transactions");
	if (!txa || !json_is_array(txa)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	tx_count = json_array_size(txa);
	tx_size = 0;
	for (i = 0; i < tx_count; i++) {
		const json_t *tx = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tx, "data"));
		if (!tx_hex) {
			applog(LOG_ERR, "JSON invalid transactions");
			goto out;
		}
		tx_size += strlen(tx_hex) / 2;
	}

	/* build coinbase transaction */
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
		cbtx_size = cbtx_hex ? strlen(cbtx_hex) / 2 : 0;
		cbtx = malloc(cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (!pk_script_size) {
			if (allow_getwork) {
				applog(LOG_INFO, "No payout address provided, switching to getwork");
				have_gbt = false;
			} else
				applog(LOG_ERR, "No payout address provided");
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp);
		cbtx = malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx+5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
		cbtx_size = 43;
		/* BIP 34: height in coinbase */
		for (n = work->height; n; n >>= 8)
			cbtx[cbtx_size++] = n & 0xff;
		cbtx[42] = cbtx_size - 43;
		cbtx[41] = cbtx_size - 42; /* scriptsig length */
		le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		cbtx[cbtx_size++] = 1; /* out-counter */
		le32enc((uint32_t *)(cbtx+cbtx_size), (uint32_t)cbvalue); /* value */
		le32enc((uint32_t *)(cbtx+cbtx_size+4), cbvalue >> 32);
		cbtx_size += 8;
		cbtx[cbtx_size++] = pk_script_size; /* txout-script length */
		memcpy(cbtx+cbtx_size, pk_script, pk_script_size);
		cbtx_size += pk_script_size;
		le32enc((uint32_t *)(cbtx+cbtx_size), 0); /* lock time */
		cbtx_size += 4;
		coinbase_append = true;
	}
	if (coinbase_append) {
		unsigned char xsig[100];
		int xsig_len = 0;
		if (*coinbase_sig) {
			n = strlen(coinbase_sig);
			if (cbtx[41] + xsig_len + n <= 100) {
				memcpy(xsig+xsig_len, coinbase_sig, n);
				xsig_len += n;
			} else {
				applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
			}
		}
		tmp = json_object_get(val, "coinbaseaux");
		if (tmp && json_is_object(tmp)) {
			void *iter = json_object_iter(tmp);
			while (iter) {
				unsigned char buf[100];
				const char *s = json_string_value(json_object_iter_value(iter));
				n = s ? strlen(s) / 2 : 0;
				if (!s || n > 100 || !hex2bin(buf, s, n)) {
					applog(LOG_ERR, "JSON invalid coinbaseaux");
					break;
				}
				if (cbtx[41] + xsig_len + n <= 100) {
					memcpy(xsig+xsig_len, buf, n);
					xsig_len += n;
				}
				iter = json_object_iter_next(tmp, iter);
			}
		}
		if (xsig_len) {
			unsigned char *ssig_end = cbtx + 42 + cbtx[41];
			int push_len = cbtx[41] + xsig_len < 76 ? 1 :
			               cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
			n = xsig_len + push_len;
			memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
			cbtx[41] += n;
			if (push_len == 2)
				*(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
			if (push_len)
				*(ssig_end++) = xsig_len;
			memcpy(ssig_end, xsig, xsig_len);
			cbtx_size += n;
		}
	}

	//n = varint_encode(txc_vi, 1 + tx_count);
	work->txs = malloc(2 * (n + cbtx_size + tx_size) + 1);
	bin2hex(work->txs, txc_vi, n);
	bin2hex(work->txs + 2*n, cbtx, cbtx_size);

	/* generate merkle root */
	merkle_tree = malloc(32 * ((1 + tx_count + 1) & ~1));
	//sha256d(merkle_tree[0], cbtx, cbtx_size);
	for (i = 0; i < tx_count; i++) {
		tmp = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
		const int tx_size = tx_hex ? strlen(tx_hex) / 2 : 0;
		unsigned char *tx = malloc(tx_size);
		if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
			applog(LOG_ERR, "JSON invalid transactions");
			free(tx);
			goto out;
		}
		//sha256d(merkle_tree[1 + i], tx, tx_size);
		if (!submit_coinbase)
			strcat(work->txs, tx_hex);
	}
	n = 1 + tx_count;
	while (n > 1) {
		if (n % 2) {
			memcpy(merkle_tree[n], merkle_tree[n-1], 32);
			++n;
		}
		n /= 2;
		//for (i = 0; i < n; i++)
		//	sha256d(merkle_tree[i], merkle_tree[2*i], 64);
	}

	/* assemble block header */
	work->data[0] = swab32(version);
	for (i = 0; i < 8; i++)
		work->data[8 - i] = le32dec(prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	work->data[17] = swab32(curtime);
	work->data[18] = le32dec(&bits);
	memset(work->data + 19, 0x00, 52);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[7 - i] = be32dec(target + i);

	tmp = json_object_get(val, "workid");
	if (tmp) {
		if (!json_is_string(tmp)) {
			applog(LOG_ERR, "JSON invalid workid");
			goto out;
		}
		work->workid = strdup(json_string_value(tmp));
	}

	/* Long polling */
	tmp = json_object_get(val, "longpollid");
	if (want_longpoll && json_is_string(tmp)) {
		free(lp_id);
		lp_id = strdup(json_string_value(tmp));
		if (!have_longpoll) {
			char *lp_uri;
			tmp = json_object_get(val, "longpolluri");
			lp_uri = json_is_string(tmp) ? strdup(json_string_value(tmp)) : rpc_url;
			have_longpoll = true;
			tq_push(thr_info[longpoll_thr_id].q, lp_uri);
		}
	}

	rc = true;

out:
	free(cbtx);
	free(merkle_tree);
	return rc;
	#endif
}

static void share_result(int result, const char *reason)
{
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
	
}



static bool get_upstream_work(CURL *curl, struct work *work)
{
	
}

static void workio_cmd_free(struct workio_cmd *wc)
{

}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
	
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{

}

static void *workio_thread(void *userdata)
{
	
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	
}

bool fulltest_le(const uint *hash, const uint *target) {
    
}

static int scanhash_neoscrypt(int thr_id, uint *pdata, const uint *ptarget,
  uint max_nonce, uint *hashes_done, uint profile) {
  
}



#if defined(ASM) && defined(MINER_4WAY)
static int scanhash_neoscrypt_4way(int thr_id, uint *pdata,
  const uint *ptarget, uint max_nonce, uint *hashes_done, uchar *scratchpad) {
    
}

#endif /* (ASM) && (MINER_4WAY) */

static void *miner_thread(void *userdata)
{
	#if 0
	struct thr_info *mythr = userdata;
	int thr_id = mythr->id;
	struct work work = {{0}};
	uint32_t max_nonce;
	uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
	char s[16];
	int i;

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	if (!opt_benchmark) {
		setpriority(PRIO_PROCESS, 0, 19);
		drop_policy();
	}

	/* Cpu affinity only makes sense if the number of threads is a multiple
	 * of the number of CPUs */
	if (num_processors > 1 && opt_n_threads % num_processors == 0) {
		if (!opt_quiet)
			applog(LOG_INFO, "Binding thread %d to cpu %d",
			       thr_id, thr_id % num_processors);
		affine_to_cpu(thr_id, thr_id % num_processors);
	}


    uchar *scratchbuf = NULL;
#if defined(ASM) && defined(MINER_4WAY)
    const size_t align = 0x40;
    if(opt_neoscrypt_asm == 2) {
        if(opt_algo == ALGO_NEOSCRYPT) {
            scratchbuf = (uchar *) malloc(134464 + align);
        }
#if defined(SHA256) && !defined(NEOMIN)
        else if(opt_algo == ALGO_ALTSCRYPT) {
            scratchbuf = (uchar *) malloc(525632 + align);
        }
#endif /* SHA256 */
    } else
#endif /* (ASM) && (MINER_4WAY) */
#ifndef NEOMIN
    if(opt_algo == ALGO_SCRYPT) {
        scratchbuf = scrypt_buffer_alloc();
    }
#endif


    while(1) {
        uint hashes_done;
		struct timeval tv_start, tv_end, diff;
		int64_t max64;
		int rc;

        if(have_stratum) {

            while(time(NULL) >= g_work_time + 120)
              sleep(1);

            while(!stratum.job.diff) {
                applog(LOG_DEBUG, "Waiting for Stratum to set the job difficulty");
                sleep(1);
            }

            pthread_mutex_lock(&g_work_lock);
            if(work.data[19] >= end_nonce && !memcmp(work.data, g_work.data, 76))
              stratum_gen_work(&stratum, &g_work);

        } else {
			int min_scantime = have_longpoll ? LP_SCANTIME : opt_scantime;
			/* obtain new work from internal workio thread */
			pthread_mutex_lock(&g_work_lock);
			if (!have_stratum &&
			    (time(NULL) - g_work_time >= min_scantime ||
			     work.data[19] >= end_nonce)) {
				if (unlikely(!get_work(mythr, &g_work))) {
					applog(LOG_ERR, "work retrieval failed, exiting "
						"mining thread %d", mythr->id);
					pthread_mutex_unlock(&g_work_lock);
					goto out;
				}
				g_work_time = have_stratum ? 0 : time(NULL);
			}
			if (have_stratum) {
				pthread_mutex_unlock(&g_work_lock);
				continue;
			}
		}
		if (memcmp(work.data, g_work.data, 76)) {
			work_free(&work);
			work_copy(&work, &g_work);
			work.data[19] = 0xffffffffU / opt_n_threads * thr_id;
		} else
			work.data[19]++;
		pthread_mutex_unlock(&g_work_lock);
		work_restart[thr_id].restart = 0;
		
		/* adjust max_nonce to meet target scan time */
		if (have_stratum)
			max64 = LP_SCANTIME;
		else
			max64 = g_work_time + (have_longpoll ? LP_SCANTIME : opt_scantime)
			      - time(NULL);
		max64 *= thr_hashrates[thr_id];

                if(max64 <= 0)
                  switch(opt_algo) {

                    case(ALGO_NEOSCRYPT):
#ifdef SHA256
                    case(ALGO_ALTSCRYPT):
#endif
                    case(ALGO_SCRYPT):
                        max64 = 0x3FFFF;
                        if(opt_nfactor > 3)
                          max64 >>= (opt_nfactor - 3);
                        if(opt_nfactor > 16)
                          max64 = 0xF;
                        break;

                    case(ALGO_SHA256D):
                        max64 = 0x1FFFFF;
                        break;

                }

		if (work.data[19] + max64 > end_nonce)
			max_nonce = end_nonce;
		else
			max_nonce = work.data[19] + max64;
		
		hashes_done = 0;
		gettimeofday(&tv_start, NULL);

        /* Hash and verify against targets */
        switch(opt_algo) {

            case(ALGO_NEOSCRYPT):
#if defined(ASM) && defined(MINER_4WAY)
                if(opt_neoscrypt_asm == 2)
                  rc = scanhash_neoscrypt_4way(thr_id, work.data, work.target,
                    max_nonce, &hashes_done,
                    (uchar *) &scratchbuf[(size_t)scratchbuf & (align - 1)]);
                else
#endif
                 rc = scanhash_neoscrypt(thr_id, work.data, work.target,
                    max_nonce, &hashes_done, opt_neoscrypt_profile);
                break;

		default:
			/* should never happen */
			goto out;
		}


		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
			pthread_mutex_lock(&stats_lock);
            thr_hashrates[thr_id] =
              (ullong)hashes_done / (diff.tv_sec + 1e-6 * diff.tv_usec);
			pthread_mutex_unlock(&stats_lock);
		}
		if (!opt_quiet) {
			sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.3f",
				1e-3 * thr_hashrates[thr_id]);
            applog(LOG_INFO, "thread %d: %u hashes, %s KH/s", thr_id, hashes_done, s);
		}
		if (opt_benchmark && thr_id == opt_n_threads - 1) {
			double hashrate = 0.;
			for (i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
				hashrate += thr_hashrates[i];
			if (i == opt_n_threads) {
				sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.3f", 1e-3 * hashrate);
				applog(LOG_INFO, "Total: %s KH/s", s);
			}
		}

		/* if nonce found, submit work */
		if (rc && !opt_benchmark && !submit_work(mythr, &work))
			break;
		
	}

out:
	tq_freeze(mythr->q);

    if(scratchbuf) free(scratchbuf);

	return NULL;
	#endif
}

static void restart_threads(void)
{
	
}

static void *longpoll_thread(void *userdata)
{
	
}

static bool stratum_handle_response(char *buf)
{

}

static void *stratum_thread(void *userdata)
{
	
}

static void show_version_and_exit(void)
{
	
}

static void show_usage_and_exit(int status)
{

}

static void strhide(char *s)
{
	//if (*s) *s++ = 'x';
	//while (*s) *s++ = '\0';
}

static void parse_config(json_t *config, char *pname, char *ref);

static void parse_arg(int key, char *arg, char *pname)
{


}

static void parse_config(json_t *config, char *pname, char *ref)
{

}

static void parse_cmdline(int argc, char *argv[])
{
	
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		//applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		//applog(LOG_INFO, "SIGINT received, exiting");
		exit(0);
		break;
	case SIGTERM:
		//applog(LOG_INFO, "SIGTERM received, exiting");
		exit(0);
		break;
	}
}
#endif


int miner_main(int argc, char *argv[])
{
	//struct thr_info *thr;
	//long flags;
	//int i;
//pthread_mutex_init(&stratum.work_lock, NULL);
   // printf("NeoScrypt CPUminer v%u.%u.%u\n",
   //   VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);


   
    uint opt_flags = 0;

#ifdef MINER_4WAY

   // if(opt_flags & 0x00000020) opt_neoscrypt_asm = 2;
#else
    
   // if(opt_flags & 0x00000020) opt_neoscrypt_asm = 1;
#endif

	// strdup SUSPICOUS for gdata
	//rpc_user = ("");
	//rpc_pass = ("");

	//parse command line
	//parse_cmdline(argc, argv);



        //printf("Engines: ");
#ifdef ASM
#ifdef MINER_4WAY
        //printf("INT SSE2 SSE2-4way (enabled: ");
        //if(opt_neoscrypt_asm == 2)
       //   printf("SSE2-4way)\n");
#else
        //printf("INT SSE2 (enabled: ");
#endif // MINER_4WAY  
        //if(opt_neoscrypt_asm == 1)
        //  printf("SSE2)\n");
        //if(!opt_neoscrypt_asm)
         // printf("INT)\n");
#else
        //printf("INT (enabled: INT)\n");
#endif // ASM * /

        //if(opt_algo == ALGO_NEOSCRYPT) {
       //     opt_neoscrypt_profile =
        //      0x80000020 | (opt_nfactor << 8) | ((opt_neoscrypt_asm & 0x1) << 12);
        //}



	//if (!rpc_userpass) {
		//rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		// SUSPICOUS:
		//sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	//}


	//pthread_mutex_init(&applog_lock, NULL);
	//pthread_mutex_init(&stats_lock, NULL);
	//pthread_mutex_init(&g_work_lock, NULL);
	////pthread_mutex_init(&stratum.sock_lock, NULL);
	
	//miner_thread(0);
	
	while(1) {
		usleep(1000);
	}
}
