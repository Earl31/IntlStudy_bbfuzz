
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

#include "sdpscan.h"

using namespace std;

bProfile* pProfile; // not a global variable

static void _profile_desc(void *value, void *user)
{
	char szName[MAX_LEN_PROFILEDESCRIPTOR_UUID_STR];
	char szUUID[MAX_LEN_UUID_STR];
	sdp_profile_desc_t *desc = (sdp_profile_desc_t*)value;
	
	sdp_uuid2strn(&desc->uuid, szUUID, MAX_LEN_UUID_STR); // necessary? not sure...
	memcpy(&pProfile->uuid, &desc->uuid, sizeof(uuid_t));
	//uuid_copy(pProfile->uuid, &desc->uuid);
	
	sdp_profile_uuid2strn(&desc->uuid, szName, sizeof(szName));
	pProfile->name = szName;
	
	if (desc->version)
		pProfile->version = desc->version;
}

static void _service_desc(void *value, void *user)
{
	sdp_data_t *p = (sdp_data_t*)value;
	sdp_data_t *s = NULL;
	char szName[MAX_LEN_PROTOCOL_UUID_STR];
	char szUUID[MAX_LEN_UUID_STR];
	int i = 0, proto = 0;
	
	if (pProfile == NULL)
	{
		printf("[-] error: pProfile is NULL\n");
		return;
	}
	bProtocol tmpproto;
	//pProfile->protocols.push_back(bProtocol());
	
	for (; p; p = p->next, i++)
	{
		switch (p->dtd)
		{
		case SDP_UUID16:
		case SDP_UUID32:
		case SDP_UUID128:
			sdp_uuid2strn(&p->val.uuid, szUUID, MAX_LEN_UUID_STR); // necessary? not sure...
			memcpy(&tmpproto.uuid, &p->val.uuid, sizeof(uuid_t));
			//memcpy(&pProfile->protocols.back().uuid, &p->val.uuid, sizeof(uuid_t));
			
			// get name of current protocol
			sdp_proto_uuid2strn(&p->val.uuid, szName, sizeof(szName));
			tmpproto.name = szName;
			//pProfile->protocols.back().name = szName;
			
			proto = sdp_uuid_to_proto(&p->val.uuid);
			break;
		case SDP_UINT8:
			if (proto == RFCOMM_UUID)
				tmpproto.channel = p->val.uint8;
				//pProfile->protocols.back().channel = p->val.uint8;
			else
				tmpproto.uint8 = p->val.uint8;
				//pProfile->protocols.back().uint8 = p->val.uint8;
			break;
		case SDP_UINT16:
			if (proto == L2CAP_UUID)
			{
				if (i == 1)
				{ // PSM
					tmpproto.psm = p->val.uint16;
					//pProfile->protocols.back().psm = p->val.uint16;
				}
				else
				{ // version
					tmpproto.version = p->val.uint16;
					//pProfile->protocols.back().version = p->val.uint16;
				}
			}
			/*
			else if (proto == BNEP_UUID)
			{}
			else
			{}
			*/
			break;
		
		case SDP_SEQ16:
		case SDP_SEQ8:
		default:
			break;
		}
	}
	if (proto == SDP_UUID)
		pProfile->protocols.push_back(new prtSDP(tmpproto));
	else if (proto == RFCOMM_UUID)
		pProfile->protocols.push_back(new prtRFCOMM(tmpproto));
	else if (proto == L2CAP_UUID)
		pProfile->protocols.push_back(new prtL2CAP(tmpproto));
	else if (proto == OBEX_UUID)
		pProfile->protocols.push_back(new prtOBEX(tmpproto));
	else
		pProfile->protocols.push_back(new bProtocol(tmpproto));
}


static void _access_protos(void *value, void *user)
{
	sdp_list_t *protDescSeq = (sdp_list_t*)value;
	sdp_list_foreach(protDescSeq, _service_desc, 0);
}

static void _obex_psm_check(void *value, void* user)
{
	sdp_data_t *p = (sdp_data_t*)value;
	if (p->attrId == 0x200 && p->dtd == SDP_UINT16)
	{ /* attrId GOEP L2CAP PSM = 0x200 */
		*(int*)user = p->val.uint32;
		//printf("data: %04x\n", p->val.uint32);
	}
}

static void _set_attr(sdp_record_t *rec, vector<bProfile> &bprofiles)
{
	sdp_list_t *list = NULL;
	sdp_list_t *proto = NULL;
	
	//sdp_record_print(rec);
	
	if (sdp_get_access_protos(rec, &proto) == 0)
	{
		// create new profile
		bprofiles.push_back(bProfile());
		pProfile = &bprofiles.back();
		
		sdp_list_foreach(proto, _access_protos, 0);
		sdp_list_foreach(proto, (sdp_list_func_t)sdp_list_free, 0);
		sdp_list_free(proto, 0);
		
		
		// check whether GOEP L2CAP PSM attribute exists or not
		int obex_psm = 0;
		if (rec && rec->attrlist)
			sdp_list_foreach(rec->attrlist, _obex_psm_check, &obex_psm);
		if (obex_psm)
		{ // GOEP L2CAP PSM exists
			for (int i = 0; i < pProfile->protocols.size(); i++)
			{ // double-check whether OBEX protocol exists or not
				if (pProfile->protocols[i]->uuid.value.uuid16 = OBEX_UUID)
					pProfile->protocols[i]->psm = obex_psm;
			}
		}
		
		
		// do not consider a profile that does not have any protocols
		if (sdp_get_profile_descs(rec, &list) == 0)
		{
			sdp_list_foreach(list, _profile_desc, 0);
			sdp_list_free(list, free);
		}
	}
	
	if (bprofiles.size() && bprofiles.back().uuid.value.uuid16 == 0 && bprofiles.back().name.length() == 0)
		bprofiles.pop_back();
}


static void _init()
{
	pProfile = NULL;
}


static int _sdpscan(char* szbtaddr, uuid_t svc_uuid, vector<bProfile> &bprofiles)
{
	int err;
	
	_init();
	
	// BDADDR_ANY
	bdaddr_t add_any = {0,0,0,0,0,0};
	
	// convert szbtaddr to bdaddr_t
	bdaddr_t target;
	str2ba(szbtaddr, &target);
	
	
	// sdp session connect
	sdp_session_t *session = NULL;
	session = sdp_connect(&add_any, &target, SDP_RETRY_IF_BUSY);
	if (!session)
	{
		printf("[-] error: sdp_connect() failed\n");
		return -1;
	}
	
	uint32_t range = 0x0000ffff;
	sdp_list_t *response_list = NULL;
	sdp_list_t *search_list = sdp_list_append(NULL, &svc_uuid);
	sdp_list_t *attrid_list = sdp_list_append(NULL, &range);
	
	
	// search all contained services
	err = sdp_service_search_attr_req(session, search_list, SDP_ATTR_REQ_RANGE, attrid_list, &response_list);
	if (err)
	{
		printf("[-] error: sdp_service_search_attr_req() failed\n");
		sdp_close(session);
		return -1;
	}
	sdp_list_free(attrid_list, 0);
	sdp_list_free(search_list, 0);
	
	
	// traversal all trees
	sdp_list_t *next;
	for (; response_list; response_list = next)
	{
		sdp_record_t *rec = (sdp_record_t*)response_list->data;
		
		// set profile data
		_set_attr(rec, bprofiles);
		
		next = response_list->next;
		free(response_list);
		sdp_record_free(rec);
	}
	
	sdp_close(session);
	return 0;
	
}


int sdpscan(char* szbtaddr, vector<bProfile> &bprofiles)
{
	uuid_t uuid;
	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);
	int ret = _sdpscan(szbtaddr, uuid, bprofiles);
	
	prtSDP *psdp = new prtSDP();
	psdp->name = "SDP";	
	bProfile bp;
	bp.name = "SDP";
	bp.protocols.push_back(psdp);
	bprofiles.push_back(bp);
	
	for (int i = 0; i < bprofiles.size(); i++)
	{
		bprofiles[i].szbtaddr = szbtaddr;
		
		for(int j = 0; j < bprofiles[i].protocols.size(); j++)
		{
			bprofiles[i].protocols[j]->pProfile = &bprofiles[i];
		}
	}

	//psdp->free();
	
	return ret;
}
