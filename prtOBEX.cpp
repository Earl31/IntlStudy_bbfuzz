
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

#include "prtOBEX.h"
#include <errno.h>

using namespace std;

extern FILE *fi;


prtOBEX::prtOBEX()
	:sock(0), connection_id(0), put_cnt(0)
{
}

prtOBEX::prtOBEX(const bProtocol &p)
	:bProtocol(p), sock(0), connection_id(0), put_cnt(0)
{
}

prtOBEX::~prtOBEX()
{
	this->free();
}

prtOBEX::prtOBEX(const prtOBEX &p)
	:bProtocol((const bProtocol&)p)
{
	sock = p.sock;
	memcpy(&addr_l2, &p.addr_l2, sizeof(sockaddr_l2));
	memcpy(&addr_rc, &p.addr_rc, sizeof(sockaddr_rc));
}

bProtocol* prtOBEX::Clone()
{
	return new prtOBEX(*this);
}

int prtOBEX::connect()
{
	int ret;
	//if (((bProfile*)pProfile)->version == 0x100)
	if (!this->psm)
		ret = _connect_rfcomm();
	else
		ret = _connect_l2cap();
	
	if (ret) /* error in connection process */
		return ret;
	
	
	
	char packet[1024];
	obex_hdr *phdr = (obex_hdr*)packet;
	obex_hdr_connect *phdr_connect = (obex_hdr_connect*)(packet + OBEX_HDR_SIZE);
	
	phdr->opcode = OBEX_OP_CONNECT | OBEX_OP_FINAL;
	phdr->len = bswap_16(OBEX_HDR_SIZE + OBEX_HDR_CONNECT_SIZE); // __cpu_to_be16?
	phdr_connect->version = 0x10;
	phdr_connect->flags = 0;
	phdr_connect->maxlen = bswap_16(PAYLOAD_SIZE); // __cpu_to_be16?
	
	ret = ::send(sock, packet, OBEX_HDR_SIZE + OBEX_HDR_CONNECT_SIZE, 0);
//	ret = this->send(packet, OBEX_HDR_SIZE + OBEX_HDR_CONNECT_SIZE);
	if (ret <= 0)
	{
		printf("[-] prtOBEX::connect, send() failed\n");
		this->free();
		return -1;
	}
	
	::recv(sock, packet, 1024, 0);
	if (!(phdr->opcode & OBEX_OP_SUCCESS))
	{
		printf("[-] prtOBEX::connect, recv opcode: %02X\n", phdr->opcode);
		this->free();
		return -1;
	}
	
	phdr->len = bswap_16(phdr->len);
	if (phdr->len == 7)
		return 0;
	else if (phdr->len == 12 && (unsigned char)packet[7] == OBEX_HDR_CONNECTIONID)
	{
		connection_id = bswap_32(*(uint32_t*)(&packet[8]));
	}
	else
	{
		printf("[-] prtOBEX::connect,  unknown option: %02X, %d\n", (unsigned char)packet[7], phdr->len);
		this->free();
		return -1;
	}
	
	return 0;
}

int prtOBEX::_connect_l2cap()
{
	sock = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_L2CAP);
	//sock = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sock < 0)
	{
		printf("[-] prtOBEX::_connect_l2cap, socket() failed\n");
		return -1;
	}
	
	memset(&addr_l2, 0, sizeof(addr_l2));
	addr_l2.l2_family = AF_BLUETOOTH;
	addr_l2.l2_psm = htobs(this->psm);	
	str2ba(((bProfile*)(this->pProfile))->szbtaddr, &addr_l2.l2_bdaddr);
	if (::connect(sock, (struct sockaddr*)&addr_l2, sizeof(addr_l2)) < 0)
	{
		printf("[-] prtOBEX::_connect_l2cap, connect() failed\n");
		printf("[-] %s\n", strerror(errno));
		close(sock);
		sock = 0;
		return -1;
	}
	
	return 0;
}

int prtOBEX::_connect_rfcomm()
{
	sock = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sock < 0)
	{
		printf("[-] prtOBEX::_connect_rfcomm, socket() failed\n");
		return -1;
	}
	
	bProfile *pProfile = (bProfile*)this->pProfile;
	int rfc_channel = -1;
	for (int i = 0; i < pProfile->protocols.size(); i++)
	{
		if (pProfile->protocols[i]->uuid.value.uuid16 == RFCOMM_UUID)
			rfc_channel = pProfile->protocols[i]->channel;
	}
	if (rfc_channel == -1)
	{
		printf("[-] prtOBEX::_connect_rfcomm, cannot find rfcomm channel\n");
		close(sock);
		sock = 0;
		return -1;
	}
	
	memset(&addr_rc, 0, sizeof(addr_rc));
	addr_rc.rc_family = AF_BLUETOOTH;
	addr_rc.rc_channel = (uint8_t) rfc_channel;
	str2ba(((bProfile*)(this->pProfile))->szbtaddr, &addr_rc.rc_bdaddr);
	if (::connect(sock, (struct sockaddr*)&addr_rc, sizeof(addr_rc)) < 0)
	{
		printf("[-] prtOBEX::_connect_rfcomm, connect() failed\n");
		printf("[-] %s\n", strerror(errno));
		close(sock);
		sock = 0;
		return -1;
	}
	
	return 0;
}


int prtOBEX::free()
{
	if (sock)
		close(sock);
	sock = 0;
	return 0;
}

char pack[65536]={0};
int prtOBEX::send(char *s, int size)
{
	int size2=0;

	if (!sock)
		return -1;

	memset(pack,0,sizeof(pack));
	
	if(!put_cnt){
		//obex_hdr *phdr = (obex_hdr*)s;
		//obex_hdr_put *puthdr = (obex_hdr_put*)(s+OBEX_HDR_PUT_SIZE);
		obex_hdr_put *puthdr = (obex_hdr_put*)(pack);
		puthdr->opcode = OBEX_OP_PUT;
		puthdr->len = bswap_16(OBEX_HDR_PUT_SIZE+size);
		puthdr->connection_id_hdr = OBEX_HDR_CONNECTIONID;
		puthdr->connection_id = bswap_32(connection_id);
		puthdr->name_hdr=OBEX_HDR_NAME;
		puthdr->name_len=bswap_16(13);
		puthdr->name[0]=0x7400;
		puthdr->name[1]=0x6500;
		puthdr->name[2]=0x7300;
		puthdr->name[3]=0x7400;
		puthdr->name[4]=0x0000;
		puthdr->len_hdr = OBEX_HDR_LENGTH;
		puthdr->file_len = bswap_32(DEFAULT_ITERATION*size);
		puthdr->bdy_hdr = OBEX_HDR_BODY;
		puthdr->bdy_hdr_len = bswap_16(size+3);
		memcpy(pack+OBEX_HDR_PUT_SIZE,s,size);
		size2=OBEX_HDR_PUT_SIZE;

		//fprintf(fi,"PUT(1 byte) | Length(2 bytes) | Opcode(1 byte)| Connection id(4 bytes)| Opcode(1 byte)| Name Length(2 bytes) | test(name, 5 byte) | Opcode(1 byte) | File Length(4 bytes) | Opcode(1 byte) | Length(2 bytes) | Body |\n");
		fprintf(fi,"1\nsend|1|");
	}

	else{
		if(put_cnt==1) fprintf(fi,"2\n");
		//obex_hdr *phdr = (obex_hdr*)s;
		obex_hdr_put_cont *puthdr = (obex_hdr_put_cont*)(pack);
		puthdr->opcode = OBEX_OP_PUT;
		puthdr->len = bswap_16(size+6);
		puthdr->bdy_hdr = OBEX_HDR_BODY;
		puthdr->bdy_hdr_len = bswap_16(size+3);
		memcpy(pack+6,s,size);
		size2=6;

		//fprintf(fi,"PUT(1 byte) | Length(2 bytes) | Opcode(1 byte) | Length(2 bytes) | Body |\n");
		fprintf(fi,"send|");
	}
	//return ::write(sock, s, size);
	put_cnt++;

	if(put_cnt==DEFAULT_ITERATION){
		write(sock, pack, size);

		//obex_hdr *phdr = (obex_hdr*)s;
		memset(pack,0,sizeof(pack));
		obex_hdr_put_cont *puthdr = (obex_hdr_put_cont*) (pack);
		puthdr->opcode = OBEX_OP_PUT;
		puthdr->len = bswap_16(6);
		puthdr->bdy_hdr = OBEX_HDR_ENDOFBODY;
		puthdr->bdy_hdr_len = bswap_16(3);

		//fprintf(fi,"PUT(1 byte) | Length(2 bytes) | End Of Body(1 byte) | Length(2 bytes) |\n");
		fprintf(fi,"send|3|");
	
		return write(sock, pack, 6);

	}
	return write(sock, pack, size+size2);
}

int prtOBEX::recv(char *s, int size)
{
	if (!sock)
		return -1;
	
	return ::recv(sock, s, size, 0);
}

int prtOBEX::reconnect()
{
	this->free();
	return this->connect();
}
