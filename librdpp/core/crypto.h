#ifndef _RDPP_CORE_CRYPTO_H_
#define _RDPP_CORE_CRYPTO_H_

#include <core/config.h>
#include <core/buffer.h>

namespace rdpp {

	inline void security_uint32_le(uint8_t *output, uint32_t value)
	{
		output[0] = (value) & 0xFF;
		output[1] = (value >> 8) & 0xFF;
		output[2] = (value >> 16) & 0xFF;
		output[3] = (value >> 24) & 0xFF;
	}

	inline void security_uint64_le(uint8_t *output, uint64_t value)
	{
		output[0] = (value) & 0xFF;
		output[1] = (value >> 8) & 0xFF;
		output[2] = (value >> 16) & 0xFF;
		output[3] = (value >> 24) & 0xFF;
		output[4] = (value >> 32) & 0xFF;
		output[5] = (value >> 40) & 0xFF;
		output[6] = (value >> 48) & 0xFF;
		output[7] = (value >> 56) & 0xFF;
	}

	class Rsa
	{
    public:
        static const uint32_t EXPONENT_MAX_SIZE = 4;
        static const uint32_t TSSK_KEY_LENGTH = 64;

		static bool random(uint8_t *output, int len);
		static bool random(Buffer &output, int len);
		static string random(int len);
		static bool generateKey(Buffer &n, Buffer &e, Buffer &d);
        static int public_encrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* exponent, uint8_t* output);
        static int public_decrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* exponent, uint8_t* output);
        static int private_encrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* private_exponent, uint8_t* output);
        static int private_decrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* private_exponent, uint8_t* output);
        static void crypto_reverse(uint8_t *data, int length);        
    private:
        static int rsa_common(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* exponent, int exponent_size, uint8_t* output);
        static int rsa_public(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* exponent, uint8_t* output)
        {
            return rsa_common(input, length, key_length, modulus, exponent, EXPONENT_MAX_SIZE, output);
        }
        static int rsa_private(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* private_exponent, uint8_t* output)
        {
            return rsa_common(input, length, key_length, modulus, private_exponent, key_length, output);
        }
    };

	class HMac
	{
	public:
		HMac();
		~HMac();
		bool init(const char *md, const void *key, int keylen);
		bool update(const void *input, size_t ilen);
		bool final(void *output, int olen);
		static bool HMAC(const char *md, const void *key, int keylen,
						 const void *input, size_t ilen,
						 void *output, int olen);
	private:
		void *_ctx;
	};

	class Digest
	{
	public:
		static const int SHA1_LENGTH = 20;
		static const int MD5_DIGEST_LENGTH = 16;
		static const int MD4_DIGEST_LENGTH = 16;

		Digest();
		~Digest();
		bool init(const char *md);
		bool update(const uint8_t *input, int ilen);
		bool update(const string &input);
		bool final(uint8_t *output, int olen);
		static bool digest(const char *md, const uint8_t *input, 
			               int ilen, uint8_t *output, int olen);
		static bool MD4(const uint8_t *input, int ilen, uint8_t *output, int olen);
		static bool MD5(const uint8_t *input, int ilen, uint8_t *output, int olen);
	private:
		void *_ctx;
	};

	class Rc4
	{
	public:
		Rc4();
		~Rc4();
		bool setup(const uint8_t *key, int keylen);
		bool update(int length, const uint8_t *input, uint8_t *output);
		static bool rc4k(const uint8_t *key, int keylen, 
			             int length, const uint8_t *input, uint8_t *output);
	private:
		void freeCtx();
		void *_ctx;
	};

	class Cipher
	{
	public:
		Cipher();
		~Cipher();
		bool init(const char *cipher, bool encrypt, const uint8_t *key, const uint8_t *iv);
		bool update(const uint8_t *input, int ilen, uint8_t *output, int *olen);
		bool final(uint8_t *output, int *olen);
	private:
		void *_ctx;
	};

} // namespace rdpp

#endif // _RDPP_CORE_CRYPTO_H_
