#include "common.h"

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

CommonBuff::CommonBuff(u32 log_count) : count(1 << log_count), write_pos(0), read_pos(0)
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

CommonBuff::~CommonBuff()
{
	delete[] mem_pool;
}

void CommonBuff::push_buff(buff_elem& copy)
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

void CommonBuff::pop_buff(buff_elem& to)
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

void snprint_sent_status(char* buff, u32 buff_size, u32* max_prev_len, const char* str, size_t at, size_t of)
{
	Assert((at > 0) && (of > 0));

	size_t of_gib, of_mib, of_kib;
	of_gib = of_mib = of_kib = of;
	of_gib >>= 30;
	of_mib = (of_mib - (of_gib << 30)) >> 20;
	of_kib = (of_kib - (of_gib << 30) - (of_mib << 20)) >> 10;

	size_t at_gib, at_mib, at_kib;
	at_gib = at_mib = at_kib = at;
	at_gib >>= 30;
	at_mib = (at_mib - (at_gib << 30)) >> 20;
	at_kib = (at_kib - (at_gib << 30) - (at_mib << 20)) >> 10;

	u32 len = snprintf(buff, buff_size, "%s %llu.%llu.%llu / %llu.%llu.%llu (GiB.MiB.Kib)", str, at_gib, at_mib, at_kib, of_gib, of_mib, of_kib);
	u32 max_len = *max_prev_len;

	if (len > buff_size)
	{
		snprintf(buff, buff_size, "Buffer too small to display progress stats");
	}
	else if (len < max_len)
	{
		u32 diff = max_len - len;
		char* space_fill = buff + len;
		while (diff--)
		{
			*space_fill++ = ' ';
		}

		*space_fill = 0;
	}
	else
	{
		*max_prev_len = len;
	}
}