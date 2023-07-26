#pragma once

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>

using sock_t = SOCKET;
using socklen_t = int;

#define IS_SOCKET_ERROR(x) (x == SOCKET_ERROR)
#define IS_INVALID_SOCKET(s) (s == INVALID_SOCKET)
#define GET_SOCKET_ERROR() (WSAGetLastError())
#define MAX_BACK_LOG SOMAXCONN
#else
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

using sock_t = int;

#define IS_SOCKET_ERROR(x) (x < 0)
#define INVALID_SOCKET -1
#define IS_INVALID_SOCKET(s) (s < 0)
#define GET_SOCKET_ERROR() (errno)
#define MAX_BACK_LOG N_BACKLOG	
#define closesocket close
#endif

#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
//#include <istream>
//#include <iostream>
#include <filesystem>

#define Assert(Expression) if (!(Expression)) *((int *)0) = 0;

#if 0
#define DUBUG_PRINTF(str, ...) printf(str, ##__VA_ARGS__);
#else
#define DUBUG_PRINTF()
#endif

const char* get_error_text()
{
#if defined(_WIN32)
	static char message[2 << 10];
	memset(message, 0, sizeof(message));
	int error = WSAGetLastError();
	printf("\nError code: %d", error);
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0, error, 0, message, 256, 0);
	char* nl = strrchr(message, '\n');
	if (nl) *nl = 0;
	return message;
#else
	return strerror(errno);
#endif
}

bool InitializeSockets()
{
#if _WIN32
	WSADATA WsaData;
	return WSAStartup(MAKEWORD(2, 2), &WsaData) == NO_ERROR;
#else
	return true;
#endif
}

void ShutdownSockets()
{
#if _WIN32
	WSACleanup();
#endif
}

namespace fs = std::filesystem;

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

typedef float f32;
typedef double f64;

typedef u32 b32;
typedef u16 b16;
typedef u8 b8;

constexpr u32 BUFF_LOG_SIZE = 9;

namespace fs = std::filesystem;

enum class PacketType : u8
{
	Init = 0,
	Data
};

struct packet_header
{
	PacketType type;
};

#pragma pack(1)
struct packet_init
{
	size_t file_size;
	u16 name_len;
};

struct packet_data
{
	u32 size;
};

inline void
MemCopy(size_t size, void* dest_base, void* source_base)
{
	u8* source = (u8*)source_base;
	u8* dest = (u8*)dest_base;

	while (size--)
	{
		*dest++ = *source++;
	}
}

struct client_params
{
	u32 connect_ip;
	u16 connect_port;
};

struct start_params
{
	b32 start_as_server;
	std::string file_path;
	client_params client_data;
};

enum class BuffDataType : u32
{
	Name = 0,
	Data
};

struct buff_elem
{
	u8* mem;
	u32 size;
	BuffDataType type;
};

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

struct CommonBuff
{
	static constexpr u32 BUFF_ELEM_SIZE = 1 << 17;

	std::vector<buff_elem> buff;
	u8* mem_pool;
	const u32 count;
	volatile u32 read_pos, write_pos, capacity;

	std::mutex lock;
	std::condition_variable cv;

	CommonBuff(u32 log_count) : count(1 << log_count), write_pos(0), read_pos(0)
	{
		capacity = count;

		buff.resize(count);
		mem_pool = new u8[BUFF_ELEM_SIZE * (1 << log_count)];

		for (int i = 0; i < buff.size(); i++)
		{
			buff[i].mem = mem_pool + (i * BUFF_ELEM_SIZE);
			buff[i].size = 0;
		}
	}

	~CommonBuff()
	{
		delete[] mem_pool;
	}

	void push_buff(buff_elem& copy)
	{
		{
			std::unique_lock<std::mutex> lk(lock);
			cv.wait(lk, [&]{ return capacity > 0; });

			buff_elem& elem = buff[write_pos];

			write_pos = (write_pos + 1) & (count - 1);
			--capacity;

			MemCopy(copy.size, elem.mem, copy.mem);
			elem.type = copy.type;
			elem.size = copy.size;
		}

		cv.notify_all();
	}

	void pop_buff(buff_elem& to)
	{
		{
			std::unique_lock<std::mutex> lk(lock);
			cv.wait(lk, [&]{ return (read_pos != write_pos) || (capacity == 0); });

			buff_elem& from_elem = buff[read_pos];

			read_pos = (read_pos + 1) & (count - 1);
			++capacity;

			to.size = from_elem.size;
			to.type = from_elem.type;
			MemCopy(from_elem.size, to.mem, from_elem.mem);

			from_elem.size = 0;
		}

		cv.notify_all();
	}
};