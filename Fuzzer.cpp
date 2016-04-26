
/*
 *
 *  BBTestingTool - Bluetooth vulnerability testing tool
 *
 *  Copyright (C) 2015 CCS, Korea University
 *  All right reserved
 *
 *  Authors
 *   Dong-hyeok Kim     <dngthe93@korea.ac.kr>
 *   Choongin Lee       <choonginlee@korea.ac.kr>
 *   Jihwan Jeong       <askjjh@korea.ac.kr>
 *
*/

#include "Fuzzer.h"

Fuzzer::Fuzzer(bProtocol *p)
{
	this->p = p;
	this->set_default_opt();
}

Fuzzer::~Fuzzer()
{
}

int Fuzzer::set_default_opt()
{
	/* default option values are defined in global.h */
	opt_sleep_ms = DEFAULT_SLEEP_MS;
	opt_iteration = DEFAULT_ITERATION;
}

void Fuzzer::getTime(){
    struct timeval val;
    struct tm *ptm;
 
    gettimeofday(&val, NULL);
    ptm = localtime(&val.tv_sec);
  
    fprintf(fi, "%04d-%02d-%02d %02d:%02d:%02d.%06ld"
            ,ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday
            ,ptm->tm_hour,ptm->tm_min,ptm->tm_sec
            ,val.tv_usec);
}

struct sigaction old_action;

void sigint_handler(int sig_no)
{
    printf("\n\n***CTRL-C pressed, Fuzzing Module Stop***\n");
    
    struct timeval val;
    struct tm *ptm;

 	FILE *fo=fopen("log.wfl","a");
 
    gettimeofday(&val, NULL);
    ptm = localtime(&val.tv_sec);
  
    fprintf(fo, "\n%04d-%02d-%02d %02d:%02d:%02d.%06ld"
            ,ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday
            ,ptm->tm_hour,ptm->tm_min,ptm->tm_sec
            ,val.tv_usec);
  	
  	fclose(fo);

    sigaction(SIGINT, &old_action, NULL);
    kill(0, SIGINT);
}

int Fuzzer::fuzz()
{
	char payload[PAYLOAD_SIZE],rpayload[PAYLOAD_SIZE];
	char org_payld[PAYLOAD_SIZE];
	int payld_size, rpayload_size, orgpayld_size;
	int ch=0, j, cmp_size;
	fi=fopen("log.wfl","a");

	struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;
    sigaction(SIGINT, &action, &old_action);
	
	print_start();
	
	if (opt_sleep_ms)
		set_timespec();
	
	if (p->connect())
	{
		print_end();
		return -1;
	}
	
	printf("# of tested inputs : \n");
	
	for (int i = 0; i < opt_iteration; i++)
	{
		ch=0;
		if((int)(i%1000) == 999)
			printf("# of Packet Sent : %d \n", i+1);

		igen.getInput(p->uuid, payload, &payld_size);
		//printf("payload: \n");
		
		if (!i){
			_print_orgpayload(payload, payld_size);

			for(j=0;j<payld_size;j++)
				org_payld[j]=payload[j];
			orgpayld_size=payld_size;

			printf("(Press Ctrl + C if you want to quit.)\n\n");

			fprintf(fi,"bluetooth\n%s\n0.3\n",p->name.c_str());
			getTime();
			fprintf(fi,"\n");
		}
		
		//if (p->send(payload, payld_size) <= 0
		ch=p->send(payload, payld_size);
		if(ch<=0){
			//if(p->reconnect()){
				/* show previous payload */
				printf("\n[-] **SENDING FAILED**\n");
				print_payload(prev_payload, prev_size);
				_fprint_payld(payload,payld_size,1);

				/*fprintf(fi,"Compare with original packet\n");
				if(payld_size>orgpayld_size) cmp_size=orgpayld_size;
				else cmp_size=payld_size;
				for(j=0;j<cmp_size;j++){
					if(org_payld[j]==payload[j])
						fprintf(fi, "%02X ",payload[j]);
					else
						fprintf(fi, "*%02X ",payload[j]);
				}
				if(j==orgpayld_size){
					for(j=cmp_size;j<payld_size;j++)
						fprintf(fi, "*%02X ",payload[j]);
				}
				fprintf(fi,"\n");*/

				break;
			//}
		}
		else{
			_fprint_payld(payload, payld_size,0);
			ch=p->recv(rpayload,rpayload_size);
			//if(ch<=0) printf("failed\n");
		}

		
		memcpy(prev_payload, payload, payld_size);
		prev_size = payld_size;
		
		if (opt_sleep_ms)
			sleep_ms();
	}
	getTime();
	printf("\n");
	p->free();
	print_end();
	fclose(fi);
	return 0;
}

int _fprint_payld(char* payld, int size,int chk)
{
	if (!fi)
	{
		fprintf(stderr, "[-] Failed to open log file\n");
		return -1;
	}
	fprintf(fi,"%d|",size);
	if(chk==1) fprintf(fi,"*");
	for (int i = 0; i < size; i++)
	{
		//if (i % 16 == 0)
		//	fprintf(fp, "[+] ");
		fprintf(fi, "%02X", (unsigned char)payld[i]);
		if(i!=size-1) fprintf(fi," ");
		//if (i % 16 == 15)
		//	fprintf(fp, "\n");
	}

	fprintf(fi,"\n");
}

int _print_orgpayload(char* payld, int size)
{
	printf("[+] Original Packet\n");
	for (int i = 0; i < size; i++)
	{
		if (i % 16 == 0)
			printf("[+] ");
		printf("%02X ", (unsigned char)payld[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n\n");
	return 0;
}


int Fuzzer::print_payload(char* payld, int size)
{
	printf("[+] %s might be crashed. Check it out\n", this->p->name.c_str());
	for (int i = 0; i < size; i++)
	{
		if (i % 16 == 0)
			printf("[+] ");
		printf("%02X ", (unsigned char)payld[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n\n");
	return 0;
}

int Fuzzer::set_timespec()
{
	ts.tv_sec = opt_sleep_ms / 1000;
	ts.tv_nsec = (opt_sleep_ms % 1000) * 10e6;
}

int Fuzzer::sleep_ms()
{
	return nanosleep(&ts, NULL);
}

int Fuzzer::print_start()
{
	printf("-----------------------------------------------------------\n");
	printf("[+] Fuzzing start <%s>...\n", p->name.c_str());
}

int Fuzzer::print_end()
{
	printf("[+] Fuzzing end\n");
	printf("-----------------------------------------------------------\n");
	printf("\n");
}


