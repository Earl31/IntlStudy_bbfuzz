
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

#ifndef __FUZZER_H__
#define __FUZZER_H__

#include <time.h>
#include <sys/time.h>
#include <signal.h>

#include "bProtocol.h"
#include "bProfile.h"
#include "iGenerator.h"
#include "global.h"



int _print_orgpayload(char* payld, int size);
int _fprint_payld(char* payld, int size, int chk);

class Fuzzer
{
public:
	//Fuzzer();
	Fuzzer(bProtocol *p);
	~Fuzzer();
	//int set_protocol(bProtocol &p);
	int fuzz();
	
	bProtocol *p;
	iGenerator igen;
	char prev_payload[PAYLOAD_SIZE];
	int prev_size;
	
	/* fuzzing options */
	int opt_sleep_ms;
	int opt_iteration;
	
private:
	int set_default_opt();
	int sleep_ms();
	int set_timespec();
	
	int print_start();
	int print_end();
	int print_payload(char* p, int s);
	void getTime();
	
	struct timespec ts;
};

#endif
