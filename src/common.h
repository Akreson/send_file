#if !defined(COMMON_H)
#define COMMON_H

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

const char* get_error_text();
bool InitializeSockets();
void ShutdownSockets();

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
	u16 size;
};

__forceinline void
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

struct CommonBuff
{
	static constexpr u16 BUFF_ELEM_SIZE = (1 << 16) - 1;

	std::vector<buff_elem> buff;
	u8* mem_pool;
	const u32 count;
	volatile u32 read_pos, write_pos, capacity;

	std::mutex lock;
	std::condition_variable cv;

	CommonBuff(u32 log_count);
	~CommonBuff();

	void push_buff(buff_elem& copy);
	void pop_buff(buff_elem& to);
};

void snprint_sent_status(char* buff, u32 buff_size, u32* max_prev_len, const char* str, size_t at, size_t of);

#endif //COMMON_H