
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

#ifndef __DEVSCAN_H__
#define __DEVSCAN_H__

#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <bluetooth/bluetooth.h>

#include "bProfile.h"
//#include "sdpscan.h"

using namespace std;

class devscan
{
public:
	devscan();
	~devscan();

	string name;
	string bt_addr;
	vector<bProfile> profiles;
};

void finddev();

#endif
