#include "client.h"

static sock_t set_server_con(client_params ConnParams)
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

	if (IS_SOCKET_ERROR(connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr))))
	{
		printf("Error connect call faild: %s\n", get_error_text());
		exit(EXIT_FAILURE);
	}

	return sock;
}

static void read_file_loop(read_loop_param& params)
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

static u32 set_init_packet(u8* mem, std::string& path)
{
	fs::path file_name(path);
	file_name = file_name.filename();
	size_t file_size = fs::file_size(path);

	u8* write_ptr = mem;

	packet_header header;
	header.type = PacketType::Init;

	packet_init init_body = {};
	init_body.file_size = file_size;
	init_body.name_len = file_name.string().length();

	*(packet_header*)write_ptr = header;
	write_ptr += sizeof(packet_header);

	*(packet_init*)write_ptr = init_body;
	write_ptr += sizeof(packet_init);

	for (auto ch : file_name.string())
	{
		*write_ptr++ = ch;
	}

	u32 result_size = write_ptr - mem;
	return result_size;
}

void start_as_client(client_params conn_params, std::string& path)
{
	char progress_buff[256];
	u8 header_buff[2 << 10];
	u32 max_progress_buff_len = 0;

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
				snprint_sent_status(progress_buff, sizeof(progress_buff), &max_progress_buff_len, "Sent", file_sent_bytes, file_size);
				printf("%s\r", progress_buff);
			}
		} while (data_to_send);
	}

	printf("%s\n", progress_buff);
	if (file_sent_bytes == file_size)
	{
		printf("Entire file has been sent");
	}
	else
	{
		printf("File hasn't been sent entirely");
	}

	fs_reader.join();
	closesocket(connection);
	delete[] send_elem.mem;
}