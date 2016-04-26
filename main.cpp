
/*
 *
 *  BBTestingTool - Bluetooth vulnerability testing tool
 *
 *  Copyright (C) 2015 CCS, Korea University
 *  All right reserved
 *
 *  Authors
 *   Dong-hyeok Kim	<dngthe93@korea.ac.kr>
 *   Choongin Lee	<choonginlee@korea.ac.kr>
 *   Jihwan Jeong	<askjjh@korea.ac.kr>
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <asm/byteorder.h>

#include "bProtocol.h"
#include "bProfile.h"
#include "Fuzzer.h"
#include "devscan.h"
#include "sdpscan.h"
#include "strategy.h"
#include "pairing.h"
#include "global.h"


#include "prtOBEX.h"


int profile_fuzz();

int test_main()
{
	char addr[] = "7C:66:9D:B0:88:30";
	
	bProfile profile;
	prtOBEX* pobex = new prtOBEX();
	pobex->channel = 12;
	profile.szbtaddr = addr;
	profile.protocols.push_back(pobex);
	profile.protocols[0]->pProfile = &profile;
	
	
	profile.protocols[0]->connect();
	//profile.protocols[0]->send("asd", 4);
	profile.protocols[0]->free();	
	
	return 0;
}


int main(int argc, char* argv[])
{	
	
	//int s = strategy();
	
	/*switch(s)
	{
	case 1:
	// no.1 pairing level analysis
		if(pairing_check() < 0)
		{
			return 0; // pairing checking err
		}
		printf("Pairing checking completed.\n");
		break;
	
	case 2:
	// no.2 profile level (protocols)
		profile_fuzz();	
		break;
	default:
		break;
	}*/

	printf("\nBlackBox Testing - Bluetooth Fuzzer ver. 1.2\n");
	profile_fuzz();
	
    return 0;

}



int profile_fuzz()
{	
	/* test code - add S-Link device */

	printf("\n");
	printf("[+] Start scanning bluetooth devices...\n");
	printf("(Press Ctrl + C if you want to quit.)\n");
	finddev();
	if(devices.size() == 0)
	{
		printf("[-] No device found. Please try again.\n");
		return 0;
	}
	
	printf("\n	Target Bluetooth Device List\n");
	printf("	[No.]\t[BT address]\t\t[Device name]\n");
	for (int i = 0; i < devices.size(); i++)
		printf("	%02d\t%s\t%s\n", i, devices[i].bt_addr.c_str(), devices[i].name.c_str());
	
	printf("	Total : %ld\n\n", devices.size());

	int device_num = -1;
	printf("\nselect device(exit : -1): ");
	scanf("%d", &device_num);
	if(device_num==-1) return 0;
	while (device_num < 0 || device_num >= devices.size())
	{
		printf("wrong device number\n");
		printf("select device: ");
		scanf("%d", &device_num);
	}
	devscan *pDev_s = &devices[device_num];
	
	/* sdp scan module start */
	
	printf("\nStart scanning services...\n");
	printf("(Press Ctrl + C if you want to quit.)\n\n");
	//sdpscan((char*)devices[device_num].bt_addr.c_str(), devices[device_num].profiles);
	int ret=sdpscan((char*)pDev_s->bt_addr.c_str(), pDev_s->profiles);
	if(ret==-1){
		printf("\n***Fuzzing Module Stop***\n\n");
		return 0;
	}
	
	/* sdp scan module complete */
	
	
	//printf("profiles.size(): %ld\n", devices[device_num].profiles.size());
	for (int i = 0; i < pDev_s->profiles.size(); i++)
	{
		//printf("\t%02d\t[0x%04x]: %s\n", i, devices[device_num].profiles[i].uuid.value.uuid16, devices[device_num].profiles[i].name.c_str());
		printf("\t%02d\t[0x%04x]: %s\n", i, pDev_s->profiles[i].uuid.value.uuid16, pDev_s->profiles[i].name.c_str());
		/*
		for (int j = 0; j < profiles[i].protocols.size(); j++)
			printf("\t    [0x%04x]: %s\n", j, devices[device_num].profiles[i].protocols[j].uuid.value.uuid16, devices[device_num].profiles[i].protocols[j].name.c_str());
		*/
	}
	
	int prof_num = -1;
	printf("\nSelect a profile to fuzz(exit : -1): ");
	scanf("%d", &prof_num);
	if(prof_num==-1) return 0;
	//while (prof_num < 0 || prof_num >= devices[device_num].profiles.size())
	while (prof_num < 0 || prof_num >= pDev_s->profiles.size())
	{
		printf("Wrong profile number\n");
		printf("Select a profile to fuzz(exit : -1): ");
		scanf("%d", &prof_num);
	}
	printf("\n");
	if(prof_num==-1) return 0;
	//bProfile *pProfile_s = &devices[device_num].profiles[prof_num];
	bProfile *pProfile_s = &pDev_s->profiles[prof_num];
	
	
	printf("\t00\t[0x0000]: ALL protocols\n");
	for (int i = 0; i < pProfile_s->protocols.size(); i++)
		printf("\t%02d\t[0x%04x]: %s\n", i + 1, pProfile_s->protocols[i]->uuid.value.uuid16, pProfile_s->protocols[i]->name.c_str());
	
	
	int proto_num = -1;
	printf("Select a protocol to fuzz(exit : -1): ");
	scanf("%d", &proto_num);
	while (proto_num < -1 || proto_num > devices[device_num].profiles[prof_num].protocols.size())
	{
		printf("Wrong protocol number\n");
		printf("Select a protocol to fuzz(exit : -1): ");
		scanf("%d", &proto_num);
	}
	if(proto_num==-1) return 0;
	printf("\n\n");

	FILE *fo;
	fo=fopen("log.wfl","w");
	fprintf(fo,"%s\n",pDev_s->bt_addr.c_str());
	fclose(fo);
	
	if (!proto_num)
	{ // fuzz ALL protocols
		for (int i = 0; i < pProfile_s->protocols.size(); i++)
		{
			Fuzzer fuzz(pProfile_s->protocols[i]);
			fuzz.fuzz();
		}
	}
	else
	{ // fuzz specific protocol
		Fuzzer fuzz(pProfile_s->protocols[proto_num - 1]);
		fuzz.fuzz();
	}
	
	
	return 0;
}



int main1(int argc, char* argv[])
{
	struct sockaddr_l2 addr;
	l2cap_cmd_hdr *cmd;
	int sock;
	char* bdstr_addr = argv[1];
	
	sock = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if ( sock < 0 )
	{
		printf("sock() error\n");
		return 1;
	}
	
	
	memset(&addr, 0, sizeof(addr));
	addr.l2_family =  AF_BLUETOOTH;
	if ( bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
	{
		printf("bind() error\n");
		return 1;
	}
	
	
	str2ba(bdstr_addr, &addr.l2_bdaddr);
	if ( connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
	{
		printf("connect() error\n");
		return 1;
	}
	
	{
		char buf[1024];
		int i;
		l2cap_cmd_hdr *cmd = (l2cap_cmd_hdr*)buf;
		cmd->code = 1;
		cmd->ident = 1;
		cmd->len = __cpu_to_le16(10);
		for (i = L2CAP_CMD_HDR_SIZE; i < 1024; i++)
		{
		}
	}
	
	
	
	return 0;
}
