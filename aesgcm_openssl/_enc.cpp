#include "_enc.h"

namespace GoodLib
{
	class ProcessFinished : public std::exception
	{
	public:
		char* what()
		{
			return (char*)"Process Finished";
		}
	};

	class KeyNotCorrect : public std::exception
	{
	public:
		const char* what()
		{
			return "Key Not Correct";
		}
	};

	class CreateNewObject : public std::exception
	{
	public:
		char* what()
		{
			return (char*)"Create New Object";
		}
	};

	class FileNotFound : public std::exception
	{
	private:
		const char* msg;

	public:
		FileNotFound(const char* _msg) : msg(_msg) {}
		const char* what()
		{
			return msg;
		}
	};

	aesgcm::aesgcm(std::string _key, std::string _input_file, std::string _output_file)
		: key(_key), input_file(_input_file), output_file(_output_file)
	{
		std::memset(key32, 0, 32);
	}

	void aesgcm::derive_key(const char* key, const char* salt, const size_t salt_len, char* out)
	{
		PKCS5_PBKDF2_HMAC(key, std::strlen(key), (unsigned char*)salt, salt_len, 100000, EVP_sha256(), 32, (unsigned char*)out);
	}

	int aesgcm::encrypt_chunk()
	{
		if (func_called == 2)
			throw CreateNewObject();

		if (!std::filesystem::exists(input_file))
			throw FileNotFound(input_file.string().c_str());

		if (key32[0] == '\0')
		{
			char salt[32];
			RAND_bytes((unsigned char*)salt, 32);
			derive_key(key.c_str(), salt, 32, key32);

			std::fstream fout(output_file, std::ios::out | std::ios::binary);
			fout.write(salt, 32);
			fout.close();

			func_called = 1;
		}

		if (std::filesystem::exists(input_file) != processed)
		{
			std::fstream fin(input_file, std::ios::in | std::ios::binary);
			std::fstream fout(output_file, std::ios::app | std::ios::binary);

			fin.seekg(to_seek);

			int64_t remaining_bytes = std::filesystem::file_size(input_file) - to_seek;
			int64_t size = remaining_bytes < 10 * (1 << 20) ? remaining_bytes : 10 * (1 << 20);

			char* data = new char[size];
			fin.read(data, size);
			to_seek = fin.tellg();

			char nonce[12];
			RAND_bytes((unsigned char*)nonce, 12);

			char* ciphertext = new char[size + 16];
			int len;
			ctx = EVP_CIPHER_CTX_new();
			EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
			EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char*)key32, (unsigned char*)nonce);
			EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext, &len, (unsigned char*)data, size);
			EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext + len, &len);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &ciphertext[size]);
			EVP_CIPHER_CTX_free(ctx);

			int64_t bytes_read = fin.gcount();
			processed += bytes_read;

			fout.write((char*)nonce, sizeof nonce);
			fout.write(ciphertext, size + 16);
			fin.close();
			fout.close();

			return (int)bytes_read;
		}
		else
		{
			throw ProcessFinished();
		}
	}

	int aesgcm::decrypt_chunk()
	{
		if (func_called == 1)
			throw CreateNewObject();

		if (!std::filesystem::exists(input_file))
			throw FileNotFound(input_file.string().c_str());

		if (key32[0] == '\0')
		{
			std::fstream fin(input_file, std::ios::in | std::ios::binary);
			char salt[32];
			fin.read(salt, 32);
			derive_key(key.c_str(), salt, 32, key32);

			to_seek = fin.tellg();
			fin.close();
			func_called = 2;
			processed = 32;

			if (std::filesystem::exists(output_file))
				std::filesystem::remove(output_file);
		}

		if (std::filesystem::exists(input_file) != processed)
		{
			std::fstream fin(input_file, std::ios::in | std::ios::binary);
			std::fstream fout(output_file, std::ios::app | std::ios::binary);

			fin.seekg(to_seek);

			char nonce[12];
			fin.read(nonce, 12);
			processed += 12;

			int64_t remaining_bytes = (std::filesystem::file_size(input_file) - to_seek) - 12;
			int64_t size = remaining_bytes < (10 * (1 << 20) + 16) ? remaining_bytes : (10 * (1 << 20) + 16);
			char* cipher = new char[size];
			fin.read(cipher, size);
			to_seek = fin.tellg();
			
			char* decrypted_data = new char[size - 16];
			int len;
			ctx = EVP_CIPHER_CTX_new();
			EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
			EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*)key32, (unsigned char*)nonce);
			EVP_DecryptUpdate(ctx, (unsigned char*)decrypted_data, &len, (unsigned char*)cipher, size - 16);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, &cipher[size - 16]);
			EVP_DecryptFinal_ex(ctx, (unsigned char*)cipher + len, &len);
			EVP_CIPHER_CTX_free(ctx);

			int64_t bytes_read = fin.gcount();
			processed += bytes_read;

			fout.write(decrypted_data, size - 16);
			fin.close();
			fout.close();

			return (int)bytes_read;
		}
		else
		{
			throw ProcessFinished();
		}
	}

	bool aesgcm::encrypt()
	{
		//if (!finished())
		//{
		//	while (!finished())
		//		encrypt_chunk();
		//}
		//else
		//{
		//	throw ProcessFinished();
		//}
	}

	bool aesgcm::decrypt()
	{
		//if (!finished())
		//{
		//	while (!finished())
		//		decrypt_chunk();
		//}
		//else
		//{
		//	throw ProcessFinished();
		//}
	}

	uintmax_t aesgcm::total()
	{
		if (!std::filesystem::exists(input_file))
			throw FileNotFound(input_file.string().c_str());
		return std::filesystem::file_size(input_file);
	}

	bool aesgcm::finished()
	{
		if (std::filesystem::exists(input_file))
		{
			return std::filesystem::file_size(input_file) == processed;
		}
		else
		{
			return 0;
		}
	}

	bool aesgcm::verify_key()
	{
		std::fstream fin(input_file, std::ios::in | std::ios::binary);

		char salt[32];
		fin.read(salt, 32);

		char _key32[32];
		derive_key(key.c_str(), salt, 32, _key32);

		char nonce[12];
		fin.read(nonce, 12);

		int64_t remaining_bytes = (std::filesystem::file_size(input_file) - to_seek) - 12;
		int64_t size = remaining_bytes < (10 * (1 << 20) + 16) ? remaining_bytes : (10 * (1 << 20) + 16);
		char* cipher = new char[size];
		fin.read(cipher, size);

		char* decrypted_data = new char[size - 16];
		int len;
		ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
		EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char*)_key32, (unsigned char*)nonce);
		EVP_DecryptUpdate(ctx, (unsigned char*)decrypted_data, &len, (unsigned char*)cipher, size - 16);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, &cipher[size - 16]);
		int ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)cipher + len, &len);
		EVP_CIPHER_CTX_free(ctx);
		return ret > 0 ? true : false;
	}
}
