#if !defined(SERVER_H)
#define SERVER_H

#include "common.h"

enum class ServerProcessState : u8
{
	Init,
	InitBody,
	DataChunk,
	OngoingData
};

struct ServerRecvState
{
	ServerProcessState state;
	u8* read_ptr;
	size_t file_size;
	size_t recved_bytes;

	union
	{
		struct
		{
			u16 name_len;
			u16 name_left;
		} init_body;

		struct
		{
			u32 size;
			u32 left;
		} data_body;
	};
};

void start_as_server();

#endif //SERVER_H