
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

#ifndef __PRTOBEX_H__
#define __PRTOBEX_H__

#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <asm/byteorder.h>

#include "bProfile.h"
#include "bProtocol.h"
#include "global.h"

class prtOBEX : public bProtocol
{
public:
	prtOBEX();
	prtOBEX(const bProtocol &p);
	prtOBEX(const prtOBEX &p);
	~prtOBEX();

	virtual int connect();
	virtual int free();
	virtual int send(char *s, int size);
	virtual int recv(char *s, int size);
	virtual int reconnect();
	virtual bProtocol* Clone();
	
	int sock;
	int put_cnt;
	int connection_id;
	struct sockaddr_l2 addr_l2;
	struct sockaddr_rc addr_rc;
	
private:
	int _connect_l2cap();
	int _connect_rfcomm();

};


#define OBEX_OP_FINAL 0X80

#define OBEX_OP_CONNECT 0x00
#define OBEX_OP_PUT 0X02
#define OBEX_OP_CONTINUE 0x10
#define OBEX_OP_SUCCESS 0X20

#define OBEX_HDR_NAME 0x01
#define OBEX_HDR_BODY 0x48
#define OBEX_HDR_LENGTH 0xC3
#define OBEX_HDR_CONNECTIONID 0xCB
#define OBEX_HDR_ENDOFBODY 0x49

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

typedef struct {
	uint8_t		opcode;
	uint16_t	len;
} __attribute__ ((packed)) obex_hdr;
#define OBEX_HDR_SIZE 3

typedef struct {
	uint8_t		version;
	uint8_t		flags;
	uint16_t	maxlen;
} __attribute__ ((packed)) obex_hdr_connect;
#define OBEX_HDR_CONNECT_SIZE 4

typedef struct {
	uint8_t		opcode;
	uint16_t	len;
	uint8_t		version;
	uint8_t		flags;
	uint16_t	maxlen;
} __attribute__ ((packed)) obex_connect;

#pragma pack(pop)

typedef struct {
	uint8_t		opcode;
	uint16_t	len;
	uint8_t		connection_id_hdr;
	uint32_t	connection_id;
	uint8_t		name_hdr;
	uint16_t	name_len;
	uint16_t	name[5];
	uint8_t		len_hdr;
	uint32_t	file_len;
	uint8_t		bdy_hdr;
	uint16_t	bdy_hdr_len;
} __attribute__ ((packed)) obex_hdr_put;
#define OBEX_HDR_PUT_SIZE 29

typedef struct {
	uint8_t		opcode;
	uint16_t	len;
	uint8_t		bdy_hdr;
	uint16_t	bdy_hdr_len;
} __attribute__ ((packed)) obex_hdr_put_cont;

#ifdef __cplusplus
}

#endif

#endif

