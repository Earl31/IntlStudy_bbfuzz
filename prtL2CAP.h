
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

#ifndef __PRTL2CAP_H__
#define __PRTL2CAP_H__

#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <asm/byteorder.h>

#include "bProfile.h"
#include "bProtocol.h"
#include "global.h"

class prtL2CAP : public bProtocol
{
public:
	prtL2CAP();
	prtL2CAP(const bProtocol &p);
	prtL2CAP(const prtL2CAP &p);
	~prtL2CAP();

	virtual int connect();
	virtual int free();
	virtual int send(char *s, int size);
	virtual int recv(char *s, int size);
	virtual int reconnect();
	virtual bProtocol* Clone();
	
	int sock;
	
	/*
	int connect1();
	int free1();
	int send1(char *s, int size);
	*/
	int sock1;
	int state;
	struct sockaddr_l2 addr;
	
private:
	void choose_state();
};



#endif
