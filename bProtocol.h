
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


#ifndef __BTPROTOCOL_H__
#define __BTPROTOCOL_H__


#include <string>
#include <string.h>

#include <bluetooth/sdp.h>
	
//#include "bProfile.h"

using namespace std;


class bProtocol
{
public:
	bProtocol();
	virtual ~bProtocol();
	bProtocol(const bProtocol &b);
	
	virtual bProtocol* Clone();
	virtual int connect();
	virtual int free();
	virtual int send(char* s, int size);
	virtual int recv(char *s, int size);
	virtual int reconnect();
	
	string name;
	int psm;
	int channel;
	int uint8;
	int uint16;
	int version;
	uuid_t uuid;
	
	void *pProfile;

private:
};



#endif
