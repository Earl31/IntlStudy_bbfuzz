
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

#include "prtSDP.h"
#include <errno.h>

extern FILE *fi;

prtSDP::prtSDP()
	:sock(0), trans(0), state(0)
{
}

prtSDP::prtSDP(const bProtocol &p)
	:bProtocol(p), sock(0), trans(0), state(0)
{
}

prtSDP::prtSDP(const prtSDP &p)
	:bProtocol((bProtocol&)p)
{
	sock = p.sock;
}

prtSDP::~prtSDP()
{
	this->free();
}

bProtocol* prtSDP::Clone()
{
	return new prtSDP(*this);
}

int prtSDP::connect()
{
	int ret;
	ret = _connect_l2cap();

	if (ret)
		return ret;

	char packet[1024];
	//sleep(100);

	// will use bt_sdp_request in prtSDP.h
	
	/*bdaddr_t add_any = {0,0,0,0,0,0};

	bdaddr_t target;

	uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0xab, 0xcd };
    uuid_t svc_uuid;
    int err;
    sdp_list_t *response_list = NULL, *search_list, *attrid_list;
    sdp_session_t *session = 0;

	// convert szbtaddr to bdaddr_t
    str2ba( ((bProfile*)(this->pProfile))->szbtaddr, &target );

    // connect to the SDP server running on the remote machine
    session = sdp_connect( &add_any, &target, SDP_RETRY_IF_BUSY );
	if (!session)
	{
		printf("[-] error : sdp_connect() failed\n");
		return -1;
	}*/
}

// SDP is based on L2CAP.
int prtSDP::_connect_l2cap()
{
	sock = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sock < 0)
	{
		printf("[-] prtSDP::_connect_l2cap, socket() failed\n");
		return -1;
	}
	
	memset(&addr_l2, 0, sizeof(addr_l2));
	addr_l2.l2_family = AF_BLUETOOTH;
	addr_l2.l2_psm = htobs(SDP_PSM);
	str2ba(((bProfile*)(this->pProfile))->szbtaddr, &addr_l2.l2_bdaddr);
	if (::connect(sock, (struct sockaddr*)&addr_l2, sizeof(addr_l2)) < 0)
	{
		printf("[-] prtSDP::_connect_l2cap, connect() failed\n");
		printf("[-] %s\n", strerror(errno));
		close(sock);
		sock = 0;
		return -1;
	}
	
	return 0;
}

int prtSDP::free()
{
	if (sock)
		close(sock);
	sock = 0;
	return 0;
}

void prtSDP::choose_state(){
	printf("You can choose state which want to fuzz.\n");
	printf("(If you want to stop fuzzing, Press Ctrl + C.)\n");
	printf("=================SDP State===============\n");
	printf("(0) -> Service Search -> (1)\n");
	printf("(0) -> Attribute Search -> (2)\n");
	printf("(0) -> Service Attribute Search -> (3)\n");
	printf("=========================================\n\n");
	
	do{
		printf("Select State(1,2,3,exit : -1) : ");
		scanf("%d",&state);
		if(state==-1) exit(0);
	}while(state<1 || state>3);
	fprintf(fi,"0\n%d\n",state);
}

char sdp_packet[65536];
int prtSDP::send(char *s, int size)
{
	if(!sock)
		return -1;

	//memset(packet,0,sizeof(packet));
	if(!state) choose_state();
	sdp_searchattr_req *req_hdr = (sdp_searchattr_req*)sdp_packet;
	switch(state){
		case 2 : req_hdr->pdu_id=SDP_SVC_SEARCH_REQ; break;
		case 3 : req_hdr->pdu_id=SDP_SVC_ATTR_REQ; break;
		case 4 : req_hdr->pdu_id=SDP_SVC_SEARCH_ATTR_REQ; break;
	}
	req_hdr->transaction_id=bswap_16(trans++);
	req_hdr->len=bswap_16(size+1);
	memcpy(sdp_packet+SEARCH_ATTR_REQ_HDR_SIZE,s,size);
	sdp_packet[SEARCH_ATTR_REQ_HDR_SIZE+size]=0x00;
	//fprintf(fi,"PDU(1 byte) | Transaction id(2 bytes) | Length(2 bytes) | Packet |");
	fprintf(fi,"send|");

	return write(sock, sdp_packet, size+SEARCH_ATTR_REQ_HDR_SIZE+1);

}

int prtSDP::recv(char *s, int size)
{
	if (!sock)
		return -1;
	return ::recv(sock, s, size, 0);
}

int prtSDP::reconnect()
{
	this->free();
	return this->connect();
}

