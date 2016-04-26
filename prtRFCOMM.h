
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

#ifndef __PRTRFCOMM_H__
#define __PRTRFCOMM_H__

#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>

#include "bProtocol.h"
#include "bProfile.h"
#include "global.h"

class prtRFCOMM : public bProtocol
{
public:
	prtRFCOMM();
	prtRFCOMM(bProtocol &p);
	prtRFCOMM(prtRFCOMM &p);
	~prtRFCOMM();

	virtual int connect();
	virtual int free();
	virtual int send(char *s, int size);
	virtual int recv(char *s, int size);
	virtual int reconnect();
	virtual bProtocol* Clone();
	
	int sock;
	int state;
	struct sockaddr_rc addr_rc;
	struct sockaddr_l2 addr_l2;

private:

	void choose_state();

};



#endif
