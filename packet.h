
#ifndef __PACKET_H__
#define __PACKET_H__


#include <vector>
#include <string>

#if ( __cplusplus > 201103L )
#include <cinttypes>

#else
#include <tr1/cinttypes>

#endif

class packet
{
public:
	packet();
	~packet();
	
	std::string msg;
	int proto;
	
private:
	std::vector<uint8_t> _payload;
	int _parse_packet(uint8_t *p, int size);
};



#endif
