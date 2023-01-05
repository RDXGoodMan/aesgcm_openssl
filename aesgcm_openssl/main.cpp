#include <indicators/progress_bar.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <string.h>
#include "_enc.h"

using namespace std::literals::string_literals;
using namespace indicators;
namespace fs = std::filesystem;
namespace GL = GoodLib;

bool decrypt = false;
std::string password;

void GetStr(const char* d, char** f)
{
	printf("%s", d);

	for (int i = 0; 1; i++)
	{
		if (i)
			*f = (char*)realloc((*f), i + 1);
		else
			*f = (char*)malloc(i + 1);
		(*f)[i] = getchar();
		if ((*f)[i] == '\n')
		{
			(*f)[i] = '\0';
			break;
		}
	}
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++)
		if (!std::strncmp(argv[i], "-d", 2))
			decrypt = true;

	if (argc > 1)
	{
		if (argc == 2 && decrypt)
		{
			exit(0);
		}

		if (decrypt)
		{
			char* key = NULL;
			GetStr("Enter Key: ", &key);
			password = key;
			free(key);
		}
		else
		{
			char* key1 = NULL, * key2 = NULL;
			GetStr("Enter Key : ", &key1);
			GetStr("Enter Key again: ", &key2);
			if (!std::strcmp(key1, key2))
			{
				password = key1;
				free(key1);
				free(key2);
			}
			else
			{
				free(key1);
				free(key2);
				std::cout << "Key doesn't match";
				exit(1);
			}
		}
	}

	for (int i = 1; i < argc; i++)
	{
		if (!strncmp("-d", argv[i], 2)) continue;
		if (fs::exists(argv[i]))
		{
			if (decrypt)
			{
				fs::path path(argv[i]);
				std::string output_file((path.parent_path() / "dec - ").string() + path.filename().string());
				output_file = path.extension() == ".enc" ? fs::path(output_file).replace_extension("").string() : output_file;
				
				GL::aesgcm aes(password, argv[i], output_file);
				if (!aes.verify_key())
				{
					std::cout << argv[i] << ": KeyNotCorrect\n";
					continue;
				}

				std::string prefix = "Decrypting " + fs::path(argv[i]).filename().string() + " ";

				ProgressBar bar {
					option::BarWidth{50},
					option::Start{"["},
					option::End{"]"},
					option::Fill{"="},
					option::Lead{"<"},
					option::PrefixText{prefix},
					option::ShowPercentage{true},
					option::ShowElapsedTime{true},
					option::ShowRemainingTime{true},
					option::ForegroundColor{Color::red}  ,
					option::FontStyles{std::vector<FontStyle>{FontStyle::bold}}
				};

				uintmax_t tot = 0;
				while (!aes.finished())
				{
					tot += aes.decrypt_chunk();
					bar.set_progress(100 - ((tot / (double)aes.total()) * 100));
				}
				bar.mark_as_completed();
			}
			else
			{
				std::string output_file = argv[i] + ".enc"s;
				GL::aesgcm aes(password, argv[i], output_file);
				std::string prefix = "Encrypting " + fs::path(argv[i]).filename().string() + " ";
				ProgressBar bar{
					option::BarWidth{60},
					option::Start{"["},
					option::End{"]"},
					option::Fill{"="},
					option::Lead{">"},
					option::PrefixText{prefix},
					option::ShowPercentage{true},
					option::ShowElapsedTime{true},
					option::ShowRemainingTime{true},
					option::ForegroundColor{Color::green}  ,
					option::FontStyles{std::vector<FontStyle>{FontStyle::bold}}
				};

				uintmax_t tot = 0;
				while (!aes.finished())
				{
					tot += aes.encrypt_chunk();
					bar.set_progress((tot / (double)aes.total()) * 100);
				}
			}
		}
		else
		{
			std::cout << argv[i] << " Not Found\n";
		}
	}
	return 0;
}


//void print_hex(const CryptoPP::byte* in, size_t len_in) noexcept
//{
//	std::string result;
//	CryptoPP::StringSource(in, len_in, true,
//		new CryptoPP::HexEncoder(
//			new CryptoPP::StringSink(result)
//		)
//	);
//	std::cout << "hex: " << result << std::endl;
//}