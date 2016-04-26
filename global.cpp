
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

#include "global.h"

//vector<bProfile> profiles;
vector<devscan> devices;
vector<devscan> hcidevs;

bdaddr_t snf_bdr;
bdaddr_t inq_bdr;
bdaddr_t m_bdr;
bdaddr_t s_bdr;

FILE *fi;