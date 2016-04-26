
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

#include <string>


#include "bProfile.h"
#include "bProtocol.h"



using namespace std;


//vector<bProfile> profiles;

bProfile::bProfile()
	:code(0), version(0), szbtaddr(NULL)
{
	memset(&(this->uuid), 0, sizeof(uuid_t));
}

bProfile::~bProfile()
{
	for (int i = 0; i < protocols.size(); i++)
		delete protocols[i];
}

bProfile::bProfile(const bProfile &b)
	:name(b.name)
{
	code = b.code;
	version = b.version;
	memcpy(&uuid, &b.uuid, sizeof(uuid_t));
	for (int i = 0; i < b.protocols.size(); i++)
	{
		protocols.push_back(b.protocols[i]->Clone());
		protocols[i]->pProfile = this;
	}
	
	szbtaddr = b.szbtaddr;
}




