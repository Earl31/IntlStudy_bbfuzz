/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id: bdaddr.c,v 1.3.2 2008/02/08 00:02:32 ^_^ Exp $
 *  $Id: bdaddr.c,v 1.1.1.1 2005/12/27 14:31:21 bytebeater Exp $
 *  $Id: bdaddr.c,v 1.3 2005/04/20 16:54:53 holtmann Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <iostream>
#include <typeinfo>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define OCF_ERICSSON_WRITE_BD_ADDR	0x000d
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) ericsson_write_bd_addr_cp;
#define ERICSSON_WRITE_BD_ADDR_CP_SIZE 6

static int ericsson_write_bd_addr(int dd, bdaddr_t *bdaddr)
{
	struct hci_request rq;
	ericsson_write_bd_addr_cp cp;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = OCF_ERICSSON_WRITE_BD_ADDR;
	rq.cparam = &cp;
	rq.clen   = ERICSSON_WRITE_BD_ADDR_CP_SIZE;
	rq.rparam = NULL;
	rq.rlen   = 0;

	if (hci_send_req(dd, &rq, 1000) < 0)
		return -1;

	return 0;
}

#if 0
#define OCF_ERICSSON_STORE_IN_FLASH	0x0022
typedef struct {
	uint8_t		user_id;
	uint8_t		flash_length;
	uint8_t		flash_data[253];
} __attribute__ ((packed)) ericsson_store_in_flash_cp;
#define ERICSSON_STORE_IN_FLASH_CP_SIZE 255

static int ericsson_store_in_flash(int dd, uint8_t user_id, uint8_t flash_length, uint8_t *flash_data)
{
	struct hci_request rq;
	ericsson_store_in_flash_cp cp;

	memset(&cp, 0, sizeof(cp));
	cp.user_id = user_id;
	cp.flash_length = flash_length;
	if (flash_length > 0)
		memcpy(cp.flash_data, flash_data, flash_length);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = OCF_ERICSSON_STORE_IN_FLASH;
	rq.cparam = &cp;
	rq.clen   = ERICSSON_STORE_IN_FLASH_CP_SIZE;
	rq.rparam = NULL;
	rq.rlen   = 0;

	if (hci_send_req(dd, &rq, 1000) < 0)
		return -1;

	return 0;
}
#endif

static int csr_write_bd_addr(int dd, bdaddr_t *bdaddr)
{
	unsigned char cmd[] = { 0x02, 0x00, 0x0c, 0x00, 0x11, 0x47, 0x03, 0x70,
				0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	unsigned char cp[254], rp[254];
	struct hci_request rq;

	cmd[16] = bdaddr->b[2];
	cmd[17] = 0x00;
	cmd[18] = bdaddr->b[0];
	cmd[19] = bdaddr->b[1];
	cmd[20] = bdaddr->b[3];
	cmd[21] = 0x00;
	cmd[22] = bdaddr->b[4];
	cmd[23] = bdaddr->b[5];

	memset(&cp, 0, sizeof(cp));
	cp[0] = 0xc2;
	memcpy(cp + 1, cmd, sizeof(cmd));

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = 0x00;
	rq.event  = EVT_VENDOR;
	rq.cparam = cp;
	rq.clen   = sizeof(cmd) + 1;
	rq.rparam = rp;
	rq.rlen   = sizeof(rp);

	if (hci_send_req(dd, &rq, 2000) < 0)
		return -1;

	if (rp[0] != 0xc2) {
		errno = EIO;
		return -1;
	}

	if ((rp[9] + (rp[10] << 8)) != 0) {
		errno = ENXIO;
		return -1;
	}

	return 0;
}

#define OCF_ZEEVO_WRITE_BD_ADDR		0x0001
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) zeevo_write_bd_addr_cp;
#define ZEEVO_WRITE_BD_ADDR_CP_SIZE 6

static int zeevo_write_bd_addr(int dd, bdaddr_t *bdaddr)
{
	struct hci_request rq;
	zeevo_write_bd_addr_cp cp;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = OCF_ZEEVO_WRITE_BD_ADDR;
	rq.cparam = &cp;
	rq.clen   = ZEEVO_WRITE_BD_ADDR_CP_SIZE;
	rq.rparam = NULL;
	rq.rlen   = 0;

	if (hci_send_req(dd, &rq, 1000) < 0)
		return -1;

	return 0;
}

static struct {
	uint16_t compid;
	int (*func)(int dd, bdaddr_t *bdaddr);
} vendor[] = {
	{ 0,		ericsson_write_bd_addr	},
	{ 10,		csr_write_bd_addr	},
	{ 18,		zeevo_write_bd_addr	},
	{ 65535,	NULL			},
};

static void usage(void)
{
	printf("bdaddr - Utility for changing the Bluetooth device address\n\n");
	printf("Usage:\n"
		"\tbdaddr [-i <dev>] [new bdaddr]\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct hci_dev_info di;
	struct hci_version ver;
	bdaddr_t bdaddr;
	char addr[18];
	int i, dd, opt, dev = 0;
	bdaddr_t any = {0, 0, 0, 0, 0, 0};

	bacpy(&bdaddr, &any);

	while ((opt=getopt_long(argc, argv, "+i:h", main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			dev = hci_devid(optarg);
			if (dev < 0) {
				perror("Invalid device");
				exit(1);
			}
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	dd = hci_open_dev(dev);
	if (dd < 0) {
		fprintf(stderr, "Can't open device hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		exit(1);
	}

	if (hci_devinfo(dev, &di) < 0) {
		fprintf(stderr, "Can't get device info for hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		exit(1);
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		printf("fuck");
		fprintf(stderr, "Can't read version info for hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		exit(1);
	}

	if (!bacmp(&di.bdaddr, &any)) {
		if (hci_read_bd_addr(dd, &bdaddr, 1000) < 0) {
			fprintf(stderr, "Can't read address for hci%d: %s (%d)\n",
						dev, strerror(errno), errno);
			hci_close_dev(dd);
			exit(1);
		}
	} else
		bacpy(&bdaddr, &di.bdaddr);

	printf("Manufacturer:   %s (%d)\n",
			bt_compidtostr(ver.manufacturer), ver.manufacturer);

	ba2str(&bdaddr, addr);
	printf("Device address: %s\n", addr);

	if (argc < 1) {
		hci_close_dev(dd);
		exit(0);
	}

	str2ba(argv[0], &bdaddr);
	if (!bacmp(&bdaddr, &any)) {
		hci_close_dev(dd);
		exit(0);
	}

	for (i = 0; vendor[i].compid != 65535; i++)
		if (ver.manufacturer == vendor[i].compid) {
			ba2str(&bdaddr, addr);
			printf("New BD address: %s\n\n", addr);

			if (vendor[i].func(dd, &bdaddr) < 0) {
				fprintf(stderr, "Can't write new address\n");
				hci_close_dev(dd);
				exit(1);
			}

			printf("Address changed - Reset device now\n");

			//ioctl(dd, HCIDEVRESET, dev);
			//ioctl(dd, HCIDEVDOWN, dev);
			//ioctl(dd, HCIDEVUP, dev);

			hci_close_dev(dd);
			exit(0);
		}
		/*else {
			printf("Warning! No verified support of bdaddr for specified device. Trying ericcson_write_bd_addr function as default.\n");
			ba2str(&bdaddr, addr);
			printf("New BD address: %s\n\n", addr);
			if (vendor[0].func(dd, &bdaddr) < 0) {
				fprintf(stderr, "Can't write new address\n");
				hci_close_dev(dd);
				exit(1);
			}

			printf("Address changed - Reset device now\n");
			hci_close_dev(dd);
			exit(0);
		}*/

	hci_close_dev(dd);

	printf("\n");
	fprintf(stderr, "Unsupported manufacturer\n");

	exit(1);
}
