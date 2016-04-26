
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


#ifndef __BPROFILE_H__
#define __BPROFILE_H__


#include <string>
#include <vector>

#include "bProtocol.h"


using namespace std;


class bProfile
{
public:
	bProfile();
	~bProfile();
	bProfile(const bProfile &b);
	
	string name;
	int code;
	int version;
	uuid_t uuid;
	vector<bProtocol *> protocols;
	
	char *szbtaddr;

private:

};



#endif


