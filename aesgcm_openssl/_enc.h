#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <filesystem>
#include <string.h>
#include <iostream>
#include <fstream>

namespace GoodLib
{
	class aesgcm
	{
	private:
		int64_t processed = 0;
		int func_called = 0;
		std::streampos to_seek = 0;
		char key32[32];
		EVP_CIPHER_CTX* ctx;

	public:
		std::string key;
		std::filesystem::path input_file, output_file;

		aesgcm(std::string _key, std::string _input_file, std::string _output_file);

		int encrypt_chunk();
		int decrypt_chunk();

		bool encrypt();
		bool decrypt();

		static void derive_key(const char* key, const char* salt, const size_t salt_len, char* out);
		uintmax_t total();
		bool finished();
		bool verify_key();
	};
}
