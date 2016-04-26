
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

#ifndef __PRTSDP_H__
#define __PRTSDP_H__

#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <asm/byteorder.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "bProfile.h"
#include "bProtocol.h"
#include "global.h"

class prtSDP : public bProtocol
{
public:
	prtSDP();
	prtSDP(const bProtocol &p);
	prtSDP(const prtSDP &p);
	~prtSDP();

	virtual int connect();
	virtual int free();
	virtual int send(char *s, int size);
	virtual int recv(char *s, int size);
	virtual int reconnect();
	virtual bProtocol* Clone();
	
	int sock;
	int state;
	uint16_t trans;
	struct sockaddr_l2 addr_l2;
	
private:
	int _connect_l2cap();
	void choose_state();

};

#ifdef __cplusplus
extern "C" {
#endif

/* sdp connection definition
 * pdu(protocol data units) contains
 * the basic requests and responses
 * needed to implement the functionality of
 * Bluetooth Service Discovery.
 */
typedef struct {
	uint32_t		conID;
	uint8_t		sdpCommand;
	uint8_t		pduPayload[256];
	int			pduLength;
	uint8_t		requestResponse[256];
	int 		responseLength;
} __attribute__ ((packed)) bt_sdp_request;

typedef struct {
	uint8_t		pdu_id;
	uint16_t	transaction_id;
	uint16_t	len;
} __attribute__ ((packed)) sdp_searchattr_req;
#define SEARCH_ATTR_REQ_HDR_SIZE 5

#ifdef __cplusplus
}
#endif
#endif
