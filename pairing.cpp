
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

#include "pairing.h"

int pairing_check()
{
	int sniff_no, inq_no;
	int master_no, slave_no;

	hciscan();
	/* two devices select */
	while(true)
	{
		printf("	Enter number of a HCI device to read : ");
		scanf("%d", &sniff_no);
		if(sniff_no >= 0 && sniff_no <= (int)hcidevs.size()-1)
		{
			str2ba(hcidevs[sniff_no].bt_addr.c_str(), &snf_bdr);
			printf("	-> Device %s (%s) is set be reading device.\n", 
				hcidevs[sniff_no].name.c_str(),
				hcidevs[sniff_no].bt_addr.c_str());
			break;
		}
		printf("[-] Please enter the correct no.\n");
	}

	while(true)
	{
		printf("	Enter number of a HCI device to write : ");
		scanf("%d", &inq_no);
		if(inq_no >= 0 && inq_no <= (int)hcidevs.size()-1)
		{
			str2ba(hcidevs[inq_no].bt_addr.c_str(), &inq_bdr);
			printf("	-> Device %s (%s) is set be writing device.\n", 
				hcidevs[inq_no].name.c_str(),
				hcidevs[inq_no].bt_addr.c_str());
			break;
		}
		printf("[-] Please enter the correct no.\n");
	}

	/* test code - add S-Link device */
	devscan d;
	d.name = "S-Link for test";
	d.bt_addr = "7C:66:9D:B0:88:30";
	devices.push_back(d);
	/* test code end */
	printf("\n");
	printf("	Start scanning bluetooth devices...\n");
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

	while(true)
	{
		printf("	Enter number of master device among target devices : ");
		scanf("%d", &master_no);
		if(master_no >= 0 && master_no <= (int)devices.size()-1)
		{
			str2ba(devices[master_no].bt_addr.c_str(), &m_bdr);
			printf("	-> Device %s (%s) is set to be master device.\n", 
				devices[master_no].name.c_str(),
				devices[master_no].bt_addr.c_str());
			break;
		}
		printf("[-] Please enter the correct no.\n");
	}

	while(true)
	{
		printf("	Enter number of slave device among target devices : ");
		scanf("%d", &slave_no);
		if(slave_no == master_no)
		{
			printf("[-] Number of slave and master are same. Input again.\n");
			continue;
		}
		if(slave_no >= 0 && slave_no <= (int)devices.size()-1)
		{
			str2ba(devices[slave_no].bt_addr.c_str(), &s_bdr);
			printf("	Device %s (%s) is set to be slave device.\n", 
				devices[slave_no].name.c_str(),
				devices[slave_no].bt_addr.c_str());
			break;
		}
		printf("[-] Please enter the correct no.\n");
	}

	printf("\n	Pairing checking start ... - \n");

	// unpairing attack detection
	printf("	(1) Checking unpairing vuln. ... \n");
	if(unpair_check() < 0)
	{
		printf("[-] An error occurred during checking unpairing vulnerabilty...\n");
		return -1;
	}

	// pairing sniffing detection
	printf("	(2) Checking sniffing ... \n");
	if(sniff_check() < 0)
	{
		printf("[-] An error occurred during checking sniffing vulnerabilty...\n");
		return -1;
	}

	// pairing spoofing detection
	printf("	(3) Checking spoofing ... \n");
	if(spoof_check() < 0)
	{
		printf("[-] An error occurred during checking spoofing vulnerabilty...\n");
		return -1;
	}

	return 0;
}

int hciscan()
{
	FILE *in;
	char buff[512];

	if(!(in = popen("hciconfig", "r")))
	{
		printf("[-] HCI devices scanning failed. \n");
		return -1;
	}

	printf("\n");

	char tmpaddr[100];
	char tmpname[100];
	printf("	HCI Device List\n");
	printf("	[No.]\t[BT address]\t\t[Device name]\n");
	while(fgets(buff, sizeof(buff), in) != NULL)
	{
		if (strncmp(buff, "hci", 3) == 0)
		{
			int i = -1;
			while (buff[++i] != ':');
			buff[i] = 0;
			strcpy(tmpname, buff);
		}
		else if (strncmp(buff, "\tBD", 3) == 0)
		{
			int i = -1;
			while (buff[++i] != ':');
			strncpy(tmpaddr, &buff[i+2], 17);
			tmpaddr[17] = 0;
		}

		if(strncmp(buff, "\n", 1) == 0)
		{
			// one hci element
			hcidevs.push_back(devscan());
			hcidevs.back().name = tmpname;
			hcidevs.back().bt_addr = tmpaddr;
		}
	}

	pclose(in);

	for (int i = 0; i < hcidevs.size(); i++)
		printf("	%02d\t%s\t%s\n", i, hcidevs[i].bt_addr.c_str(), hcidevs[i].name.c_str());
	
	printf("	Total : %ld \n\n", hcidevs.size());

	return 0;
}

int unpair_check()
{
	string str_inqbdr = "";
	ba2str(&inq_bdr, (char *)str_inqbdr.c_str());
	string str_slavebdr = "";
	ba2str(&s_bdr, (char *)str_slavebdr.c_str());

	if(changebdaddr(str_inqbdr, str_slavebdr) < 0)
	{
		return -1;
	}

	return 0;

}

int changebdaddr(string dev_inq, string new_bdr)
{
	char cmd[] = "./bdaddr -i ";
	strcat(cmd, dev_inq.c_str());
	strcat(cmd, " ");
	strcat(cmd, new_bdr.c_str());

	FILE *in1, *in2;
	char buff1[512], buff2[512];

	if(!(in1 = popen(cmd, "r")))
	{
		printf("[-] Error executing address change. \n");
		return -1;
	}

	while(fgets(buff1, sizeof(buff1), in1) != NULL)
	{
		if (strstr(buff1, "Can't write new address") != NULL)
		{
			printf("[-] The hci device %s is not available for address change.\n", dev_inq.c_str());
			return -1;
		}

		if (strstr(buff1, "Address changed") != NULL)
		{
			printf("	Address is changed.\n");
			strcpy(cmd, "hciconfig -a ");
			strcat(cmd, dev_inq.c_str());
			strcat(cmd, " reset");


			if(!(in2 = popen(cmd, "r")))
			{
				printf("[-] Error executing address resetting. \n");
				return -1;
			}
			
			if(fgets(buff2, sizeof(buff2), in2) != "','")
			{
				return -1;
			}

			printf("	Address is successfully changed. \n");
			return 0;
		}
	}
	printf("	The target hci device %s is safe to address change.\n", new_bdr.c_str());
	return -1;

}

int sniff_check()
{
	return 0;
}

int spoof_check()
{
	return 0;
}
