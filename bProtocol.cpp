
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
#include "bProtocol.h"

using namespace std;

bProtocol::bProtocol()
:psm(0), channel(0), uint8(0), uint16(0), version(0), pProfile(NULL)
{
	memset(&(this->uuid), 0, sizeof(uuid_t));
}

bProtocol::~bProtocol()
{
	
}

bProtocol::bProtocol(const bProtocol &b)
	:name(b.name)
{
	psm = b.psm;
	channel = b.channel;
	uint8 = b.uint8;
	uint16 = b.uint16;
	version = b.version;
	memcpy(&uuid, &b.uuid, sizeof(uuid_t));
	pProfile = NULL;
}

bProtocol* bProtocol::Clone()
{
	return new bProtocol(*this);
}


int bProtocol::connect()
{
	printf("connect() in bProtocol\n");
	return 0;
}

int bProtocol::free()
{
	printf("free() in bProtocol\n");
	return 0;
}

int bProtocol::send(char *s, int size)
{
	printf("send() in bProtocol\n");
	return 0;
}

int bProtocol::recv(char *s, int size)
{
	printf("recv() in bProtocol\n");
	return 0;
}

int bProtocol::reconnect()
{
	printf("check() in bProtocol\n");
	return 0;
}
