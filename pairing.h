
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

#ifndef __PAIRING_H__
#define __PAIRING_H__

#include "global.h"

int pairing_check();
int hciscan();
int unpair_check();
int changebdaddr(string dev_inq, string new_bdr);
int spoof_check();
int sniff_check();

#endif
