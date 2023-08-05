#include "common.h"

sock_t get_listen_socket(int portnum)
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

void print_server_param(sock_t sock)
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

sock_t get_client(sock_t sock)
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

bool parse_params(int argc, char** argv, start_params& params)
{
	if (argc < 2)
	{
		printf("Error: arguments absent\n");
		return false;
	}

	std::vector<std::string> Args;

	for (int i = 1; i < argc; i++)
	{
		std::string Arg(argv[i]);
		Args.push_back(std::move(Arg));
	}

	std::string RunAsServer("-s");
	std::string RunAsClient("-c");
	std::string PathFlag("-f");

	if (Args[0] == RunAsServer)
	{
		params.start_as_server = true;

		if ((argc >= 4) && Args[1] == PathFlag)
		{
			params.file_path = Args[2];
		}
	}
	else if (Args[0] == RunAsClient && (Args.size() != 6))
	{
		std::string AddrFlag("-a");

		for (int arg_index = 1; arg_index < Args.size(); arg_index++)
		{
			if (Args[arg_index] == AddrFlag)
			{
				arg_index++;
				size_t colon_pos = Args[arg_index].find_first_of(":");

				if (colon_pos == std::string::npos)
				{
					printf("Invalid addres format: (ip:port)\n");
					return false;
				}

				std::string ip = Args[arg_index].substr(0, colon_pos);
				std::string port = Args[arg_index].substr(colon_pos + 1, Args[arg_index].size());

				u32 count_of_dots = 0;
				for (const char c : ip)
				{
					if (c == '.') count_of_dots++;
				}

				if (count_of_dots != 3)
				{
					printf("Invalid ip format: (X.X.X.X)\n");
					return false;
				}

				for (const char c : port)
				{
					if (c <= '0' && c >= '9')
					{
						printf("Invalid port format [0-9]\n");
						return false;
					}
				}

				inet_pton(AF_INET, ip.c_str(), &params.client_data.connect_ip);
				u32 assign_port = atoi(port.c_str());

				if (assign_port > 0xffff)
				{
					printf("Port %d is out of range\n", params.client_data.connect_port);
					return false;
				}

				params.client_data.connect_port = assign_port;
			}
			else if (Args[arg_index] == PathFlag)
			{
				++arg_index;
				if (arg_index != Args.size())
				{
					params.file_path = Args[arg_index];
				}
			}
		}

		//if (!params.client_data.connect_ip || !params.client_data.connect_port) return false;
	}
	else
	{
		printf("Ivalid params\n");
		return false;
	}

	return true;
}

void write_file_loop(CommonBuff* FileBuff)
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
				write_file.write((const char *)work_elem.mem, work_elem.size);
			} break;
		}
	}

	write_file.close();
	delete[] work_elem.mem;
}

void start_as_server()
{
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
		s32 recv_len = recv(client_sock, (char *)recv_ptr, buff_left, 0);

		if (IS_SOCKET_ERROR(recv_len))
		{
			printf("Error recv: %s\n", get_error_text());
			exit(EXIT_FAILURE);
		}
		else if (recv_len == 0)
		{
			printf("connection has been closed\n");

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
						Recv.recved_bytes += recv_len;

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
			print_sent_status("Accepted", Recv.recved_bytes, Recv.file_size);
		}
	}

	printf("End of recving process"); // todo: debug this path

	fs_writer.join();

	delete[] recv_buffer;
	delete[] accept_elem.mem;
}

sock_t set_server_con(client_params ConnParams)
{
	sock_t sock = socket(AF_INET, SOCK_STREAM, 0);
	
	if (IS_SOCKET_ERROR(sock))
	{
		printf("Error: unable create client socket: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	sockaddr_in serv_addr = {};
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = ConnParams.connect_ip;
	serv_addr.sin_port = htons(ConnParams.connect_port);

	if (IS_SOCKET_ERROR(connect(sock, (sockaddr* )&serv_addr, sizeof(serv_addr))))
	{
		printf("Error connect call faild: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	return sock;
}

struct read_loop_param
{
	CommonBuff* FileBuff;
	std::string& path;
	size_t file_size;

	read_loop_param(CommonBuff* Buff, std::string& path_name, size_t file_size) : FileBuff(Buff), path(path_name), file_size(file_size) {}
};

void read_file_loop(read_loop_param& params)
{
	CommonBuff* FileBuff = params.FileBuff;

	std::ifstream input_file;
	input_file.open(params.path, std::ifstream::in | std::ifstream::binary);
	if (!input_file.is_open())
	{
		printf("Client can't open file <%s>\n", params.path.c_str());
		exit(EXIT_FAILURE);
	}

	buff_elem read_elem = {};
	read_elem.mem = new u8[CommonBuff::BUFF_ELEM_SIZE];

	size_t left_to_read = params.file_size;
	while (left_to_read)
	{
		size_t offset = params.file_size - left_to_read;
		u32 read_size = (left_to_read > CommonBuff::BUFF_ELEM_SIZE) ? CommonBuff::BUFF_ELEM_SIZE : left_to_read;
		left_to_read -= read_size;

		input_file.seekg(offset, input_file.beg);
		input_file.read((char*)read_elem.mem, read_size);

		if (!input_file.good())
		{
			printf("File read error\n");
			exit(EXIT_FAILURE);
		}

		read_elem.size = read_size;
		read_elem.type = BuffDataType::Data;

		FileBuff->push_buff(read_elem);
	}

	read_elem.size = 0;
	FileBuff->push_buff(read_elem);
	delete[] read_elem.mem;
}

u32 set_init_packet(u8* mem, std::string& path)
{
	fs::path file_name(path);
	file_name = file_name.filename();
	size_t file_size = fs::file_size(path);

	u8* write_ptr = mem;

	packet_header header;
	header.type = PacketType::Init;

	packet_init init_body;
	init_body.file_size = file_size;
	init_body.name_len = file_name.string().length();

	*(packet_header*)write_ptr = header;
	write_ptr += sizeof(packet_header);

	*(packet_init*)write_ptr = init_body;
	write_ptr += sizeof(packet_init);

	for (auto ch : file_name.string())
	{
		if (ch == 0) __debugbreak();
		*write_ptr++ = ch;
	}

	u32 result_size = write_ptr - mem;
	return result_size;
}

void start_as_client(client_params conn_params, std::string& path)
{
	u8 header_buff[2 << 10];

	sock_t connection = set_server_con(conn_params);
	CommonBuff FileBuff(BUFF_LOG_SIZE);

	size_t file_size = fs::file_size(path);
	read_loop_param loop_param(&FileBuff, path, file_size);
	std::thread fs_reader = std::thread(read_file_loop, loop_param);

	buff_elem send_elem = {};
	send_elem.mem = new u8[CommonBuff::BUFF_ELEM_SIZE];

	ClientSendState SendState = {};
	SendState.state = ClientProcessState::Init;

	size_t total_sent_bytes = 0;
	size_t file_sent_bytes = 0;
	size_t last_sent_border = 0;

	while (1)
	{
		SendState.buff_size = 0;
		u32 packet_header_size = 0;

		switch (SendState.state)
		{
			case ClientProcessState::Init:
			{
				u32 buff_size = set_init_packet(header_buff, path);

				SendState.set_buff(header_buff, buff_size);
				SendState.state = ClientProcessState::DataHeader;

				packet_header_size = SendState.buff_size;
			} break;

			case ClientProcessState::DataBody:
			{
				SendState.set_buff(send_elem.mem, send_elem.size);
				SendState.state = ClientProcessState::DataHeader;
			} break;

			case ClientProcessState::DataHeader:
			{
				FileBuff.pop_buff(send_elem);
				if (send_elem.size && (send_elem.type == BuffDataType::Data))
				{
					packet_header header;
					packet_data data_body;

					u8* write_ptr = header_buff;

					header.type = PacketType::Data;
					data_body.size = send_elem.size;

					*(packet_header*)write_ptr = header;
					write_ptr += sizeof(packet_header);

					*(packet_data*)write_ptr = data_body;
					write_ptr += sizeof(packet_data);

					SendState.set_buff(header_buff, write_ptr - header_buff);
					SendState.state = ClientProcessState::DataBody;

					packet_header_size = SendState.buff_size;
				}
			} break;
		}

		if (!SendState.buff_size) break;

		//Assert(SendState.buff_size <= CommonBuff::BUFF_ELEM_SIZE);

		u32 data_to_send = SendState.buff_size;
		do
		{
			u32 sent_size = send(connection, (const char*)SendState.read_ptr, data_to_send, 0);

			if (IS_SOCKET_ERROR(sent_size))
			{
				printf("Error send: %s\n", get_error_text());
				exit(EXIT_FAILURE);
			}

			total_sent_bytes += sent_size;
			SendState.read_ptr += sent_size;
			data_to_send -= sent_size;

			u32 sub = (sent_size >= packet_header_size) ? packet_header_size : sent_size;
			packet_header_size -= sub;
			sent_size -= sub;
			
			file_sent_bytes += sent_size;

			if ((file_sent_bytes - last_sent_border) >= (1 << 15))
			{
				last_sent_border = file_sent_bytes;
				print_sent_status("Sent", file_sent_bytes, file_size);
			}
		} while (data_to_send);
	}

	if (file_sent_bytes == file_size)
	{
		printf("entire file has been sent");
	}
	else
	{
		printf("file has't been sent entirely");
	}

	fs_reader.join();
	closesocket(connection);
	delete[] send_elem.mem;
}

void print_help()
{
	printf("Start as server:\n");
	printf("filesend -s -f [dir_path]\n");
	printf("[dir_path] - path to directore where file will be saved\n");
	printf("\n");
	printf("Start as client:\n");
	printf("filesend -c -f [file_path] -a [server_addr]\n");
	printf("[file_path] - file wich will be send\n");
	printf("[server_addr] - server addres in format ip4:port\n");
}

int main(int argc, char** argv)
{
	if (argc == 1)
	{
		print_help();
		return 0;
	}

	start_params params = {};
	if (!parse_params(argc, argv, params)) return -1;

	InitializeSockets();

	if (params.start_as_server)
	{
		if (!params.file_path.empty())
		{
			fs::current_path(params.file_path);
		}

		start_as_server();
	}
	else
	{
		if (!params.file_path.empty())
		{
			if (fs::exists(params.file_path))
			{
				if (fs::is_directory(params.file_path))
				{
					printf("Error: <%s> is a directory not a file\n", params.file_path.c_str());
				}
				else
				{
					start_as_client(params.client_data, params.file_path);
				}

			}
			else
			{
				printf("Error: file <%s> don't exist\n", params.file_path.c_str());
			}
		}
		else
		{
			printf("Error: file to send is required\n");
		}
	}

	ShutdownSockets();
	return 0;
}