
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

#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include <bluetooth/bluetooth.h>
#include <vector>

#include "bProfile.h"
#include "devscan.h"

using namespace std;

/* options in Fuzzer class */
#define DEFAULT_SLEEP_MS 0
#define DEFAULT_ITERATION 1000000

#define PAYLOAD_SIZE 4096 // iGenerator, Database too


/* option is Database class */
#define SZ_DBNAME "data.db"

//extern vector<bProfile> profiles;
extern vector<devscan> devices;
extern vector<devscan> hcidevs;

extern bdaddr_t snf_bdr;
extern bdaddr_t inq_bdr;
extern bdaddr_t m_bdr;
extern bdaddr_t s_bdr;

extern FILE* fi;

#endif
