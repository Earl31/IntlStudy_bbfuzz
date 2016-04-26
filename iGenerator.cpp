
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

#include "iGenerator.h"

extern const char* PKT_TABLE[260];
extern int SIZE_TABLE[];

iGenerator::iGenerator()
	:cnt(0)
{
	db.open();
}

iGenerator::~iGenerator()
{
	db.close();
}

int iGenerator::getInput(uuid_t uuid, char *mut_payld, int *mut_size)
{
	int proto;
	
	/* get original packet form database */
	/* NOT IMPLEMENTED YET */
	proto = sdp_uuid_to_proto(&uuid);
	/*
	if (proto == L2CAP_UUID)
	{
		memcpy(org_payld, PKT_L2C, sizeof(PKT_L2C) - 1);
		if (!isFirst)
			org_size = sizeof(PKT_L2C) - 1;
		else
		{
			getRand(&org_size, sizeof(org_size));
			org_size %= 500;
			org_size += 4;
		}
		//for (int i = 0; i < 100; i++)
		//	org_payld[i] = (i+1)*219732173>>3;
		//org_size = 100;
	}
	else if (proto == RFCOMM_UUID)
	{
		memcpy(org_payld, PKT_RFC, sizeof(PKT_RFC) - 1);
		if (!isFirst)
			org_size = sizeof(PKT_RFC) - 1;
		else
		{
			getRand(&org_size, sizeof(org_size));
			org_size %= 500;//(sizeof(PKT_RFC) - 5);
			org_size += 5;
		}
	}
	else if (proto == OBEX_UUID)
	{
		memcpy(org_payld, PKT_OBEX, sizeof(PKT_OBEX) - 1);
		if (!isFirst)
			org_size = sizeof(PKT_OBEX) -1;
		else
		{
			getRand(&org_size, sizeof(org_size));
			org_size %= 500;//(sizeof(PKT_OBEX) - 1);
			org_size += 1;
		}
	}
	else
	{
		for (int i = 0; i < 30; i++)
			org_payld[i] = i;
		org_size = 30;
	}
	*/
	int random, id;
	srand(time(NULL));
	getRand(&random, sizeof(random));
	if(cnt>=10000 || cnt==0){
		if ((id = db.get_packet(proto, 0, random, mut_payld, mut_size)) < 1)
		{
			int size;
			if (0 < proto && proto < sizeof(PKT_TABLE) - 1){
				if(*mut_size==0)
					size=SIZE_TABLE[proto];
				else
					size=*mut_size;
				memcpy(mut_payld, PKT_TABLE[proto], size);
				*mut_size=size;
			}
			else
			{
				size=30;
				getRand(mut_payld, size);
				*mut_size = size;
			}
		}
		cnt=0;
	}
	
	else
	{
		/* scheduling the mutate function */
		/* IMPLEMENTATION DOES NOT FINISHED */
		int size;
		srand(time(NULL));
		size=*mut_size;
		if(cnt%1000==0)
			*mut_size=rand()%(size*13/10)+(size*7/10);
		mutate0(mut_payld, *mut_size, NULL);
		//genRandInput(org_payld, org_size);
	}

	cnt++;
	return 0;
}

int iGenerator::mutate0(char *payld, int size, void *opt)
{ /* opt should contain value of r and n */
	uint32_t rand32;
	int i;
	
	double r = 0.3; // <mutate byte / payload byte> [0, 1]
	int n = 1; // byte sequence
	
	for (i = 0; i < size * r; i++)
	{
		getRand(&rand32, sizeof(rand32));
		genRandInput(&payld[rand32 % (size-n+1)], n);
		//getRand(&payld[rand32 % (size-n+1)], n);
		//payld[rand32 % (size-n+1)] = rand32 >> 16;
	}
	
	return 0;
}

int iGenerator::genRandInput(char *payld, int size)
{
	double mu = 400.0;
	double sigma = 150.0;
	int i;

	for (i = 0; i < size; i++)
	{
		payld[i] = (char)genGaussianNoise(mu, sigma);
	}
}

int iGenerator::getRand(void *dst, int size)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
	{
		printf("[-] iGenerator::getRand(), open() failed\n");
		return -1;
	}
	
	if (read(fd, dst, size) < 0)
	{
		printf("[-] iGenerator::getRand(), read() failed\n");
		return -1;
	}
	
	close(fd);
}

double iGenerator::genGaussianNoise(double mu, double sigma)
{
	const double epsilon = std::numeric_limits<double>::min();
	const double tau = 2.0*3.14159265358979323846;

	static double z0;
	double u1, u2;

	do
	{
		int tmp1, tmp2;
		getRand(&tmp1, sizeof(int));
		getRand(&tmp2, sizeof(int));
		u1 = tmp1 * (1.0 / RAND_MAX);
		u2 = tmp2 * (1.0 / RAND_MAX);
	}
	while ( u1 <= epsilon );

	z0 = sqrt(-2.0 * log(u1)) * cos(tau * u2);

	return z0 * sigma + mu;
}







const char* PKT_TABLE[260] = {0, PKT_SDP, 0, PKT_RFC, 0, 0, 0, 0, PKT_OBEX, 0, 
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, PKT_AVC, 0, PKT_AVD, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, PKT_L2C, 0, 0, 0};

int  SIZE_TABLE[] = {0, sizeof(PKT_SDP)-1, 0, sizeof(PKT_RFC)-1, 0, 0, 0, 0, sizeof(PKT_OBEX)-1, 0, 
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, sizeof(PKT_AVC)-1, 0, sizeof(PKT_AVD)-1, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, sizeof(PKT_L2C)-1, 0, 0, 0};


