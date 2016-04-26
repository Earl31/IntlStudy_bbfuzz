
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

#include <stdio.h>

// Select analysis type whether it will cover paring prcess or profile.
int strategy()
{
	int type = 0;

	while(true)
	{
		printf("	Vulnerability Testing Menus\n");
		printf("	[1] Pairing process vuln.\n	[2] Profile vuln. \n");
		printf("	Please select fuction to test : ");
		scanf("	%d", &type);
		if(type == 1 || type == 2)
		{
			break;
		}
		else
		{
			printf("[-] Invalid input. please try again.\n");
		}
	}

	return type;
}
