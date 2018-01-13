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
//#include <curl/curl.h>
#include "compat.h"
#include "miner.h"
#include "version.h"

#include "neoscrypt.h"


int main(int argc, char *argv[])
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
