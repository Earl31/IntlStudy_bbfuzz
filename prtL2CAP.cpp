
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

#include "prtL2CAP.h"

extern FILE *fi;

prtL2CAP::prtL2CAP()
	:sock(0), sock1(0), state(0)
{
}

prtL2CAP::prtL2CAP(const bProtocol &p)
	:bProtocol(p), sock(0), sock1(0), state(0)
{
}

prtL2CAP::~prtL2CAP()
{
	this->free();
	//this->free1();
}

prtL2CAP::prtL2CAP(const prtL2CAP &p)
	:bProtocol((const bProtocol&)p)
{
	sock = p.sock;
	sock1 = p.sock1;
	memcpy(&addr, &p.addr, sizeof(sockaddr_l2));
}

bProtocol* prtL2CAP::Clone()
{
	return new prtL2CAP(*this);
}

/*
int prtL2CAP::connect()
{
	return 0;
}
int prtL2CAP::free()
{
	return 0;
}
int prtL2CAP::send(char *s, int size)
{
	return 0;
}
*/

int prtL2CAP::connect()
{

	sock1 = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (sock1 < 0)
	{
		printf("[-] prtL2CAP::connect1, socket() failed\n");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;


	if (bind(sock1, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		printf("[-] prtL2CAP:connect1, bind() failed\n");
		close(sock1);
		sock1 = 0;
		return -1;
	}

	str2ba(((bProfile*)(this->pProfile))->szbtaddr, &addr.l2_bdaddr);

	if (::connect(sock1, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		printf("[-] prtL2CAP::connect1, connect() failed\n");
		close(sock1);
		sock1 = 0;
		return -1;
	}
	
	return 0;
}
int prtL2CAP::free()
{
	if (sock1)
		close(sock1);
	sock1 = 0;
	return 0;
}

uint8_t l2cap_info_packet[2][16]={
	{0x0a, 0x02, 0x02, 0x00, 0x03, 0x00},
	{0x0b, 0x03, 0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};

uint8_t l2cap_packet[3][19]={
	{0x02, 0x04, 0x04, 0x00, 0x01, 0x00, 0x40, 0x00},
	{0x04, 0x05, 0x0f, 0x00, 0x40, 0x00, 0x00, 0x00, 0x04, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x05, 0x05, 0x0a, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x9b, 0x06}
};

void prtL2CAP::choose_state(){
	printf("You can choose state which want to fuzz.\n");
	printf("(If you want to stop fuzzing, Press Ctrl + C.)\n");
	printf("=================L2CAP State===============\n");
	printf("(1) -> Connect_Request -> (2)\n");
	printf("(2) -> Configure_Request -> (3)\n");
	printf("(3) -> Configure_Response -> (4)\n");
	printf("===========================================\n\n");
	
	do{
		printf("Select State(1,2,3,4,exit : -1) : ");
		scanf("%d",&state);
		if(state==-1) exit(0);
	}while(state<1 || state>4);

	int i,j;
	int size[3]={8,19,14};
	int info_size[2]={6,16};
	char rpack[30]={0};

	/*for(i=0;i<2;i++){
		write(sock1,l2cap_info_packet[i],info_size[i]);
		read(sock,rpack,30);
	}*/

	fprintf(fi,"%d\n",state-1);
	for(i=1;i<state;i++){
		write(sock1,l2cap_packet[i-1],size[i-1]);
		/*if(i==2)
			fprintf(fi,"Connection Request(1 byte) | Identifier(1 byte) | Length(2 bytes) | PSM(1 byte) |\n");
		if(i==3)
			fprintf(fi,"Configure Request(1 byte) | Identifier(1 byte) | Length(2 bytes) | DCID(2 bytes) | Flag(2 bytes) | Flow Control(11 bytes) |\n");
		if(i==4)
			fprintf(fi,"Configure Response(1 byte) | Identifier(1 byte) | Length(2 bytes) | SCID(2 bytes) | Flag(2 bytes) | Result(2 bytes) | Option(4 bytes) |\n");*/
		fprintf(fi,"send|%d|%d|",i,size[i-1]);
		for(j=0;j<size[i-1];j++){
			fprintf(fi,"%02X",l2cap_packet[i-1][j]);
			if(j!=size[i-1]-1)
				fprintf(fi," ");
		}
		fprintf(fi,"\n");
	}
	fprintf(fi,"%d\n",state);

}

int prtL2CAP::send(char *s, int size)
{
	if (!sock1)
		return -1;

	/*
	l2cap_cmd_hdr *cmd;
	char* buf;
	buf = new char[size + L2CAP_CMD_HDR_SIZE];
	static int id = 0;
	
	cmd = (l2cap_cmd_hdr*)buf;
	cmd->code = 1;
	cmd->ident = (id++%255) + 1;
	cmd->len = __cpu_to_le16(size + L2CAP_CMD_HDR_SIZE);
	
	int ret = ::send(sock1, buf, size + L2CAP_CMD_HDR_SIZE, 0);
	delete[] buf;
	return ret;
	*/

	if(!state) choose_state();

	//fprintf(fi,"Connection Request(1byte) | Identifier(1byte) | Length(2bytes) | Packet |\n");
	fprintf(fi,"send|");
	return ::send(sock1, s, size, 0);
}

int prtL2CAP::recv(char *s, int size)
{
	if (!sock)
		return -1;
	return ::recv(sock, s, size, 0);
}

int prtL2CAP::reconnect()
{
	this->free();
	return this->connect();
}
