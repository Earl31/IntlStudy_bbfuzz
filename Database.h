
#ifndef __DATABASE_H__
#define __DATABASE_H__

#include <sqlite3.h>
#include <string.h>
#include "global.h"

//#define QUERY_COUNT "SELECT COUNT(*) FROM packets WHERE proto = %d and state = %d"
#define QUERY_COUNT "SELECT COUNT(*) FROM packets WHERE proto = %d;"
//#define QUERY_GET "SELECT id, size, lower(quote(data)) FROM packets WHERE proto = %d LIMIT %d, 1;"
#define QUERY_GET "SELECT id, size, data FROM packets WHERE proto = %d LIMIT %d, 1;"

class Database
{
public:
	Database();
	~Database();
	
	int open(const char *dbname);
	int open();
	int close();
	
	int get_packet(int proto, int state, int random, char *packet, int *size);
private:
	sqlite3 *db;
};



#endif
