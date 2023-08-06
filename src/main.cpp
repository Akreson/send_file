#include "common.h"
#include "server.h"
#include "client.h"

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

void print_help()
{
	printf("Start as server:\n");
	printf("filesend -s -f [dir_path]\n");
	printf("[dir_path] - path to directore where file will be saved\n");
	printf("\n");
	printf("Start as client:\n");
	printf("filesend -c -a [server_addr] -f [file_path]\n");
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