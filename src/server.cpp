#include "server.h"

static sock_t get_listen_socket(int portnum)
{
	sock_t sock = socket(AF_INET, SOCK_STREAM, 0);
	if (IS_SOCKET_ERROR(sock))
	{
		printf("Error on creating listening socket: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	int opt = 1;
	if (IS_SOCKET_ERROR(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt))))
	{
		printf("Error setsockopt: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	sockaddr_in serv_addr = {};
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portnum);

	if (IS_SOCKET_ERROR(bind(sock, (sockaddr*)&serv_addr, sizeof(serv_addr))))
	{
		printf("Error bind: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	if (IS_SOCKET_ERROR(listen(sock, MAX_BACK_LOG)))
	{
		printf("Error listen: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	return sock;
}

static void print_server_param(sock_t sock)
{
	sockaddr_storage addr = {};
	socklen_t addr_len = sizeof(addr);

	getsockname(sock, (sockaddr*)&addr, &addr_len);

	if (addr.ss_family == AF_INET)
	{
		sockaddr_in* peer_addr = (sockaddr_in*)&addr;
		char buff[128] = {};
		const char* result = inet_ntop(AF_INET, (const void*)&peer_addr->sin_addr, buff, sizeof(buff));
		if (!result)
		{
			int error = WSAGetLastError();
			printf("Error get _ip_ in print_server_param: %s\n", get_error_text());
			exit(EXIT_FAILURE);
		}

		std::string port_str = std::to_string(ntohs(peer_addr->sin_port));
		printf("Server run on %s:%s\n", buff, port_str.c_str());
	}
}

static sock_t get_client(sock_t sock)
{
	sockaddr_in peer_addr = {};
	socklen_t peer_addr_len = sizeof(peer_addr);
	sock_t new_connect = accept(sock, (sockaddr*)&peer_addr, &peer_addr_len);

	if (IS_SOCKET_ERROR(new_connect))
	{
		printf("Error accept: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	char buff[256] = {};
	const char* result = inet_ntop(AF_INET, (const void*)&peer_addr.sin_addr.s_addr, buff, sizeof(buff));

	if (!result)
	{
		printf("Error get _ip_ in get_client: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	printf("%s is connected\n", buff);

	return new_connect;
}

static void write_file_loop(CommonBuff* FileBuff)
{
	std::ofstream write_file;
	buff_elem work_elem = {};
	work_elem.mem = new u8[CommonBuff::BUFF_ELEM_SIZE];

	while (1)
	{
		FileBuff->pop_buff(work_elem);
		if (!work_elem.size) break;

		switch (work_elem.type)
		{
			case BuffDataType::Name:
			{
				write_file.open((const char*)work_elem.mem, std::ofstream::out | std::ofstream::binary);
				if (!write_file.is_open())
				{
					printf("Can't open file\n");
					exit(EXIT_FAILURE);
				}

				printf("Start saving <%s> file\n", work_elem.mem);
			} break;

			case BuffDataType::Data:
			{
				write_file.write((const char*)work_elem.mem, work_elem.size);
			} break;
		}
	}

	write_file.close();
	delete[] work_elem.mem;
}

void start_as_server()
{
	char progress_buff[256];
	u32 max_progress_buff_len = 0;

	sock_t sock = get_listen_socket(6520);
	print_server_param(sock);

	sock_t client_sock = get_client(sock);
	closesocket(sock);

	char mss;
	socklen_t len = sizeof(mss);
	getsockopt(client_sock, IPPROTO_TCP, TCP_MAXSEG, &mss, &len);

	CommonBuff FileBuff(BUFF_LOG_SIZE);
	std::thread fs_writer(write_file_loop, &FileBuff);

	buff_elem accept_elem = {};
	accept_elem.mem = new u8[CommonBuff::BUFF_ELEM_SIZE];

	u32 recv_buffer_size = CommonBuff::BUFF_ELEM_SIZE;
	u8* recv_buffer = new u8[recv_buffer_size];
	u8* recv_ptr = recv_buffer;

	size_t prev_recv_border = 0;
	ServerRecvState Recv = {};
	Recv.state = ServerProcessState::Init;
	Recv.read_ptr = recv_buffer;

	while (1)
	{
		DUBUG_PRINTF("FileBuff.capacity %d\n", (s32)FileBuff.capacity);

		s32 buff_left = recv_buffer_size - (recv_ptr - recv_buffer);
		s32 recv_len = recv(client_sock, (char*)recv_ptr, buff_left, 0);

		if (IS_SOCKET_ERROR(recv_len))
		{
			printf("Error recv: %s\n", get_error_text());
			exit(EXIT_FAILURE);
		}
		else if (recv_len == 0)
		{
			printf("%s\n", progress_buff);
			printf("Connection has been closed\n");

			accept_elem.size = 0;
			FileBuff.push_buff(accept_elem);
			break;
		}

		DUBUG_PRINTF("recv_len: %d\n", recv_len);

		u32 buff_ptr_diff = recv_ptr - Recv.read_ptr;
		if (buff_ptr_diff)
		{
			recv_len += buff_ptr_diff;
		}

		u8* buff_end = recv_ptr + recv_len;
		while (recv_len)
		{
			switch (Recv.state)
			{
				case ServerProcessState::Init:
				{
					DUBUG_PRINTF("-- Recv.state: Init\n");

					const u32 header_size = sizeof(packet_header) + sizeof(packet_init);
					if (recv_len >= header_size)
					{
						packet_header* header = (packet_header*)Recv.read_ptr;
						Recv.read_ptr += sizeof(packet_header);
						recv_len -= sizeof(packet_header);

						if (header->type != PacketType::Init)
						{
							printf("Error at read init header\n");
							exit(EXIT_FAILURE);
						}

						packet_init* body = (packet_init*)Recv.read_ptr;
						Recv.file_size = body->file_size;

						Recv.read_ptr += sizeof(packet_init);
						recv_len -= sizeof(packet_init);

						accept_elem.type = BuffDataType::Name;
						accept_elem.size = body->name_len + 1;

						DUBUG_PRINTF("filesize: %lld | name_len: %d\n", Recv.file_size, (s32)body->name_len);
						if (recv_len >= body->name_len)
						{
							MemCopy(body->name_len, accept_elem.mem, Recv.read_ptr);

							Recv.read_ptr += body->name_len;
							recv_len -= body->name_len;

							accept_elem.mem[accept_elem.size - 1] = 0;
							Recv.state = ServerProcessState::DataChunk;

							FileBuff.push_buff(accept_elem);
							DUBUG_PRINTF("read whole name | recv_len: %d\n", recv_len);
						}
						else
						{
							MemCopy(recv_len, accept_elem.mem, Recv.read_ptr);

							Recv.init_body.name_len = body->name_len;
							Recv.init_body.name_left = body->name_len - recv_len;

							Recv.state = ServerProcessState::InitBody;
							recv_len = 0;

							DUBUG_PRINTF("name not read fully | name_len: %d | name_left: %d\n", (s32)Recv.init_body.name_len, (s32)Recv.init_body.name_left);
						}

						if (!recv_len) Recv.read_ptr = recv_ptr = recv_buffer;
					}
					else
					{
						recv_len = 0;
						recv_ptr = buff_end;
					}
				} break;

				case ServerProcessState::InitBody:
				{
					DUBUG_PRINTF("-- Recv.state: InitBody\n");
					u8* write_ptr = accept_elem.mem + (Recv.init_body.name_len - Recv.init_body.name_left);

					if (recv_len >= Recv.init_body.name_left)
					{
						MemCopy(Recv.init_body.name_left, write_ptr, Recv.read_ptr);

						Recv.read_ptr += Recv.init_body.name_left;
						recv_len -= Recv.init_body.name_left;

						accept_elem.mem[accept_elem.size - 1] = 0;
						Recv.state = ServerProcessState::DataChunk;

						FileBuff.push_buff(accept_elem);

						DUBUG_PRINTF("file name has been recved | recv_len: %d\n", recv_len);
					}
					else
					{
						MemCopy(recv_len, write_ptr, Recv.read_ptr);
						Recv.init_body.name_left -= recv_len;
						recv_len = 0;

						DUBUG_PRINTF("file name still recving | name_len: %d | name_left: %d\n", (s32)Recv.init_body.name_len, (s32)Recv.init_body.name_left);
					}

					if (!recv_len) Recv.read_ptr = recv_ptr = recv_buffer;
				} break;

				case ServerProcessState::DataChunk:
				{
					DUBUG_PRINTF("-- Recv.state: DataChunk\n");

					const u32 header_size = sizeof(packet_header) + sizeof(packet_data);
					if (recv_len >= header_size)
					{
						packet_header* header = (packet_header*)Recv.read_ptr;
						Recv.read_ptr += sizeof(packet_header);
						recv_len -= sizeof(packet_header);

						packet_data* body = (packet_data*)Recv.read_ptr;

						if (header->type != PacketType::Data)
						{
							DUBUG_PRINTF("Error at read data header <%d> | body.size: %u\n", (s32)header->type, body->size);
							exit(EXIT_FAILURE);
						}

						Recv.read_ptr += sizeof(packet_data);
						recv_len -= sizeof(packet_data);

						accept_elem.size = body->size;
						accept_elem.type = BuffDataType::Data;

						DUBUG_PRINTF("chunk size: %d\n", accept_elem.size);

						if (recv_len >= body->size)
						{
							Recv.recved_bytes += body->size;
							MemCopy(body->size, accept_elem.mem, Recv.read_ptr);

							Recv.read_ptr += body->size;
							recv_len -= body->size;

							FileBuff.push_buff(accept_elem);

							DUBUG_PRINTF("full chunk recved | recv_len: %d\n", recv_len);
						}
						else
						{
							Recv.recved_bytes += recv_len;

							MemCopy(recv_len, accept_elem.mem, Recv.read_ptr);

							Recv.data_body.size = body->size;
							Recv.data_body.left = body->size - recv_len; // TODO: fix

							Recv.state = ServerProcessState::OngoingData;
							recv_len = 0;

							DUBUG_PRINTF("chunk not fully recved | recv_len: %d | body.size: %u | body.left: %u\n", recv_len, Recv.data_body.size, Recv.data_body.left);
						}

						if (!recv_len) Recv.read_ptr = recv_ptr = recv_buffer;
					}
					else
					{
						u32 from_begin = Recv.read_ptr - recv_buffer;
						DUBUG_PRINTF("from_begin: %u | recv_len: %d\n", from_begin, recv_len);

						if (from_begin >= recv_len)
						{
							MemCopy(recv_len, recv_buffer, Recv.read_ptr);
							Recv.read_ptr = recv_buffer;
							buff_end = recv_buffer + recv_len;
						}

						recv_len = 0;
						recv_ptr = buff_end;
					}
				} break;

				case ServerProcessState::OngoingData:
				{
					DUBUG_PRINTF("-- Recv.state: OngoingData\n");
					u8* write_ptr = accept_elem.mem + (Recv.data_body.size - Recv.data_body.left);

					if (recv_len >= Recv.data_body.left)
					{
						Recv.recved_bytes += Recv.data_body.left;

						MemCopy(Recv.data_body.left, write_ptr, Recv.read_ptr);

						Recv.read_ptr += Recv.data_body.left;
						recv_len -= Recv.data_body.left;

						Recv.state = ServerProcessState::DataChunk;
						FileBuff.push_buff(accept_elem);

						DUBUG_PRINTF("ongoing chunk has been recved | recv_len: %d\n", recv_len);
					}
					else
					{
						Recv.recved_bytes += recv_len;

						MemCopy(recv_len, write_ptr, Recv.read_ptr);
						Recv.data_body.left -= recv_len;

						DUBUG_PRINTF("ongoing chunk in progress | recv_len: %d | body.size: %u | body.left: %u\n", recv_len, Recv.data_body.size, Recv.data_body.left);
						recv_len = 0;
					}

					if (!recv_len) Recv.read_ptr = recv_ptr = recv_buffer;
				} break;
			}
		}

		if ((Recv.recved_bytes - prev_recv_border) >= (1 << 15))
		{
			prev_recv_border = Recv.recved_bytes;
			snprint_sent_status(progress_buff, sizeof(progress_buff), &max_progress_buff_len, "Accepted", Recv.recved_bytes, Recv.file_size);
			printf("%s\r", progress_buff);
		}
	}

	if (Recv.recved_bytes == Recv.file_size)
	{
		printf("Entire file has been received");
	}
	else
	{
		printf("File hasn't been received entirely");
	}

	fs_writer.join();

	delete[] recv_buffer;
	delete[] accept_elem.mem;
}
