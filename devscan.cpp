
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
#include <iostream>
#include "devscan.h"
#include "sdpscan.h"
#include "global.h"

using namespace std;

//bdaddr_t master;
//bdaddr_t slave;

//contains scanned device info.
//vector<devscan> devices;

void finddev()
{
	FILE *in;
	char buff[512];


	if(!(in = popen("hcitool scan", "r")))
	{
		printf("[-] Bluetooth scanning failed. \n");
		return;
	}

	while(fgets(buff, sizeof(buff), in) != NULL){
		if (strncmp(buff, "Scan", 3) != 0){
			char tmpaddr[100];
			char tmpname[100];
			devices.push_back(devscan());
			strncpy(tmpaddr, &buff[1], 17);
			tmpaddr[17] = 0;
			strncpy(tmpname, &buff[19], sizeof(tmpname));
			if (tmpname[strlen(tmpname) - 1] == '\n')
				tmpname[strlen(tmpname) - 1] = 0;
			devices.back().name = tmpname;
			devices.back().bt_addr = tmpaddr;
		}
	}

	pclose(in);
	return;
}

devscan::devscan()
	:name("n/a"), bt_addr("00:00:00:00:00:00")
{
}

devscan::~devscan()
{
}
