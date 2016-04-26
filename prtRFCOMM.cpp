
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

#include "prtRFCOMM.h"

extern FILE *fi;

prtRFCOMM::prtRFCOMM()
	:sock(0), state(0)
{
}

prtRFCOMM::prtRFCOMM(bProtocol &p)
	:bProtocol(p), sock(0), state(0)
{
}

prtRFCOMM::prtRFCOMM(prtRFCOMM &p)
	:bProtocol((bProtocol&)p)
{
	sock = p.sock;
}

prtRFCOMM::~prtRFCOMM()
{
	this->free();
}

bProtocol* prtRFCOMM::Clone()
{
	return new prtRFCOMM(*this);
}

int prtRFCOMM::connect()
{
	/*
	sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sock < 0)
	{
		printf("[-] prtRFCOMM::connect, socket() failed\n");
		sock = 0;
		return -1;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	addr.rc_channel = (uint8_t)this->channel;
	str2ba(((bProfile*)(this->pProfile))->szbtaddr, &addr.rc_bdaddr);
	
	int ret;
	if ((ret = ::connect(sock, (struct sockaddr*)&addr, sizeof(addr))))
	{
		printf("[-] prtRFCOMM::connect, connect() failed\n");
		close(sock);
		sock = 0;
		return -1;
	}
	*/
	sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	//sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_L2CAP);
	if (sock < 0)
	{
		printf("[-] prtRFCOMM::connect, socket() failed\n");
		return -1;
	}
	
	memset(&addr_l2, 0, sizeof(addr_l2));
	addr_l2.l2_family = AF_BLUETOOTH;
	addr_l2.l2_psm = htobs(RFCOMM_PSM);
	str2ba(((bProfile*)(this->pProfile))->szbtaddr, &addr_l2.l2_bdaddr);
	if (::connect(sock, (struct sockaddr*)&addr_l2, sizeof(addr_l2)) < 0)
	{
		printf("[-] prtRFCOMM::connect, connect() failed\n");
		close(sock);
		sock = 0;
		return -1;
	}
	
	return 0;
}
int prtRFCOMM::free()
{
	if (sock)
	{
		close(sock);
		sock = 0;
	}
	return 0;
}

uint8_t rfcomm_packet[5][14]={
	{0x03, 0x3f, 0x01, 0x1c},
	{0x03, 0xef, 0x15, 0x83, 0x11, 0x18, 0xf0, 0x07, 0x00, 0xf0, 0x03, 0x00, 0x07, 0x70},
	{0x63, 0x3f, 0x01, 0xa2},
	{0x03, 0xef, 0x09, 0xe3, 0x05, 0x63},
	{0x63, 0xff, 0x01, 0x21, 0x12}
};

void prtRFCOMM::choose_state(){
	printf("You can choose state which want to fuzz.\n");
	printf("(If you want to stop fuzzing, Press Ctrl + C.)\n");
	printf("================RFCOMM State===============\n");
	printf("(1) -> SABM -> (2)\n");
	printf("(2) -> PN(Negotitation) -> (3)\n");
	printf("(3) -> SABM Channel -> (4)\n");
	printf("(4) -> MSC -> (5)\n");
	printf("(5) -> UID Channel -> (6)\n");	
	printf("===========================================\n\n");
	do{
		printf("Select State(1,2,3,4,5,6,exit : -1) : ");
		scanf("%d",&state);
		if(state==-1) exit(0);
	}while(state<1 && state>6);

	int i,j;
	int size[5]={4,14,4,6,5};
	char rpack[30]={0};

	fprintf(fi,"%d\n",state-1);
	for(i=1;i<state;i++){
		write(sock,rfcomm_packet[i-1],size[i-1]);
		//fprintf(fi,"Address(1 byte) | Control(1 byte) | Length(1 byte) | Command(n bytes) | FCS(1 byte) |\n");
		fprintf(fi,"send|%d|%d|",i,size[i-1]);
		for(j=0;j<size[i-1];j++){
			fprintf(fi,"%02X",rfcomm_packet[i-1][j]);
			if(j!=size[i-1]-1)
				fprintf(fi," ");
		}
		fprintf(fi,"\n");
		if(i<=2) read(sock,rpack,30);
	}
	fprintf(fi,"%d\n",state);

}

int prtRFCOMM::send(char *s, int size)
{
	if(!sock)
		return -1;

	if(!state) choose_state();

	/*
	SABM 0 // 03 3f 01 1c
	UIH 0 PN // 03 ef 15 83 11 18 f0 07 00 f0 03 00 07 70
	SABM CH // 63 3f 01 a2 ( CH 12 ) / CH 0110 0 / 011 FCS must be changed
	UIH 0 MSC // 03 ef 09 e3 05 63 -- CH 8d 70
	UIH CH UID // 63 ff 01 21 12
	*/

/*	switch(state){
		case 1 : break;
		case 2 : break;
		case 3 : break;
		case 4 : break;
		case 5 : break;
	}*/

	//fprintf(fi,"Address(1 byte) | Control(1 byte) | Length(1 byte) | Command(n bytes) | FCS(1 byte) |\n");
	fprintf(fi,"send|");
	return write(sock, s, size);
}

int prtRFCOMM::recv(char *s, int size)
{
	if (!sock)
		return -1;
	return read(sock, s, size);
}

int prtRFCOMM::reconnect()
{
	this->free();
	return this->connect();
}
