
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


#ifndef __SDPSCAN_H__
#define __SDPSCAN_H__

#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "bProtocol.h"
#include "bProfile.h"
#include "prtL2CAP.h"
#include "prtRFCOMM.h"
#include "prtOBEX.h"
#include "prtSDP.h"

int sdpscan(char* szbtaddr, vector<bProfile> &bprofiles);

#endif
