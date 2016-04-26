
#include "Database.h"


Database::Database()
:db(NULL)
{
}

Database::~Database()
{
}

int Database::open()
{
	return this->open(SZ_DBNAME);
}

int Database::open(const char *dbname)
{
	int ret;
	
	ret = sqlite3_open(dbname, &db);
	if (ret)
	{
		fprintf(stderr, "[-] Database::open(), sqlite3_open() failed\n");
		sqlite3_close(db);
		return -1;
	}
	
	return 0;
}

int Database::close()
{
	if (db)
	{
		sqlite3_close(db);
		db = NULL;
	}
	
	return 0;	
}

static int _atoi(char *a)
{
	int ret = 0;
	while (*a)
		ret = (ret * 10) + (*(a++) - '0');
	return ret;
}

static int _callback1(void *n, int argc, char **argv, char **azColName)
{
	int *c = (int*)n;
	
	if (argc < 1)
	{
		fprintf(stderr, "[-] Database _callback1(), argc is less than 1\n");
		return -1;
	}
	
	/* atoi */
	/*
	*n = 0;
	for (int i = 0; argv[0][i]; i++)
		*n = (*n * 10) + (argv[0][i] - '0');
	*/
	*c = _atoi(argv[0]);
	
	return 0;
}

#pragma pack(push, 1)
struct opt
{
	char* p;
	int* s;
	int* i;
};
#pragma pack(pop)

static int _callback2(void *n, int argc, char **argv, char **azColName)
{
	struct opt *parg = (struct opt*)n;
	
	if (argc != 3)
	{
		fprintf(stderr, "[-] Database _callback2(), argc is not three\n");
		return -1;
	}
	
	/* get size and do boundary check */
	*(parg->s) = _atoi(argv[1]);
	if (*(parg->s) > PAYLOAD_SIZE)
	{
		fprintf(stderr, "[-] Database _callback2(), size(%d) is greater than %d\n", *(parg->s), PAYLOAD_SIZE);
		return -2;
	}
	
	/* get id */
	*(parg->i) = _atoi(argv[0]);
	
	/* get data */
	memcpy(parg->p, argv[2], *(parg->s));
	
	return 0;
}

int Database::get_packet(int proto, int state, int random, char *packet, int *size)
{
	int ret;
	char *err = NULL;
	
	if (!db)
	{
		fprintf(stderr, "[-] Database::get_packet(), database does not opened\n");
		fprintf(stderr, "    %s\n", sqlite3_errmsg(db));
		return -1;
	}
	
	int count = 0;
	char query[1024];
	sprintf(query, QUERY_COUNT, proto/*, state*/);
	ret = sqlite3_exec(db, query, _callback1, &count, &err);
	if (ret != SQLITE_OK)
	{
		if (ret == SQLITE_ABORT)
		{
			sqlite3_free(err);
			return 0; // no result -> return id zero
		}
		fprintf(stderr, "[-] Database::get_packet(), exec1 failed\n");
		fprintf(stderr, "    %s\n", err);
		sqlite3_free(err);
		return -1;
	}
	
	if (count < 1)
	{
		//fprintf(stderr, "[-] Database::get_packet(%d, %d), cannot find packet\n", proto, state);
		return -2;
	}
	random = (random % count) + 1;
	
	int id = 0;
	struct opt arg = { packet, size, &id };
	sprintf(query, QUERY_GET, proto, random);
	ret = sqlite3_exec(db, query, _callback2, &arg, &err);
	if (ret != SQLITE_OK)
	{
		fprintf(stderr, "[-] Database::get_packet(%d, %d), _callback2 failed\n", proto, state);
		fprintf(stderr, "    %s\n", err);
		sqlite3_free(err);
		return -3;
	}
	
	return id;
}





















