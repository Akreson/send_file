#if !defined(CLIENT_H)
#define CLIENT_H

#include "common.h"

struct read_loop_param
{
	CommonBuff* FileBuff;
	std::string& path;
	size_t file_size;

	read_loop_param(CommonBuff* Buff, std::string& path_name, size_t file_size) : FileBuff(Buff), path(path_name), file_size(file_size) {}
};

enum class ClientProcessState : u8
{
	Init,
	DataBody,
	DataHeader
};

struct ClientSendState
{
	ClientProcessState state;
	u8* buff_ptr;
	u8* read_ptr;
	u32 buff_size;

	void set_buff(u8* ptr, u32 size)
	{
		read_ptr = buff_ptr = ptr;
		buff_size = size;
	}
};

void start_as_client(client_params conn_params, std::string& path);

#endif // CLIENT_H
