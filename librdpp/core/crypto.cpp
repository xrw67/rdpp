#include <core/crypto.h>
#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#define TAG "CRYPTO"

using namespace rdpp;

bool Rsa::random(uint8_t *output, int len)
{
	return (RAND_bytes(output, len) == 1);
}

bool Rsa::random(Buffer &output, int len)
{
	int ret;

	output.clear();
	output.ensureWritableBytes(len);

	ret = RAND_bytes((uint8_t *)output.beginWrite(), len);
	output.hasWritten(len);
	return (ret == 1);
}

string Rsa::random(int len)
{
	string out(len, '\0');
	if (RAND_bytes((uint8_t *)out.data(), len) == 1)
		return out;
	return "";
}

static void binnum_to_bin(const BIGNUM *a, Buffer &output)
{
	int len = BN_num_bytes(a);

	output.clear();
	output.ensureWritableBytes(len);
	BN_bn2bin(a, (uint8_t *)output.beginWrite());
	Rsa::crypto_reverse((uint8_t *)output.beginWrite(), len);
	output.hasWritten(len);
}

bool Rsa::generateKey(Buffer &n, Buffer &e, Buffer &d)
{
	RSA *r = RSA_generate_key(512, RSA_F4, NULL, NULL);
    if (r) {
		binnum_to_bin(r->n, n);
		binnum_to_bin(r->e, e);
		binnum_to_bin(r->d, d);
		e.resize(4);
        RSA_free(r);
		return true;
    }
	return false;
}

int Rsa::rsa_common(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* exponent, int exponent_size, uint8_t* output)
{
    BN_CTX* ctx;
    int output_length = -1;
    uint8_t* input_reverse;
    uint8_t* modulus_reverse;
    uint8_t* exponent_reverse;
    BIGNUM *mod, *exp, *x, *y;

    input_reverse = (uint8_t*)malloc(2 * key_length + exponent_size);
    if (!input_reverse)
        return -1;

    modulus_reverse = input_reverse + key_length;
    exponent_reverse = modulus_reverse + key_length;

    memcpy(modulus_reverse, modulus, key_length);
    crypto_reverse(modulus_reverse, key_length);
    memcpy(exponent_reverse, exponent, exponent_size);
    crypto_reverse(exponent_reverse, exponent_size);
    memcpy(input_reverse, input, length);
    crypto_reverse(input_reverse, length);

    if (!(ctx = BN_CTX_new()))
        goto fail_bn_ctx;

    if (!(mod = BN_new()))
        goto fail_bn_mod;

    if (!(exp = BN_new()))
        goto fail_bn_exp;

    if (!(x = BN_new()))
        goto fail_bn_x;

    if (!(y = BN_new()))
        goto fail_bn_y;

    BN_bin2bn(modulus_reverse, key_length, mod);
    BN_bin2bn(exponent_reverse, exponent_size, exp);
    BN_bin2bn(input_reverse, length, x);
    BN_mod_exp(y, x, exp, mod, ctx);

    output_length = BN_bn2bin(y, output);
    crypto_reverse(output, output_length);

    if (output_length < (int)key_length)
        memset(output + output_length, 0, key_length - output_length);

    BN_free(y);
fail_bn_y:
    BN_clear_free(x);
fail_bn_x:
    BN_free(exp);
fail_bn_exp:
    BN_free(mod);
fail_bn_mod:
    BN_CTX_free(ctx);
fail_bn_ctx:
    free(input_reverse);

    return output_length;
}

int Rsa::public_encrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* exponent, uint8_t* output)
{
    return rsa_public(input, length, key_length, modulus, exponent, output);
}

int Rsa::public_decrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* exponent, uint8_t* output)
{
    return rsa_public(input, length, key_length, modulus, exponent, output);
}

int Rsa::private_encrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* private_exponent, uint8_t* output)
{
    return rsa_private(input, length, key_length, modulus, private_exponent, output);
}

int Rsa::private_decrypt(const uint8_t* input, int length, uint32_t key_length, const uint8_t* modulus, const uint8_t* private_exponent, uint8_t* output)
{
    return rsa_private(input, length, key_length, modulus, private_exponent, output);
}

void Rsa::crypto_reverse(uint8_t* data, int length)
{
    int i, j;
    uint8_t temp;

    for (i = 0, j = length - 1; i < j; i++, j--) {
        temp = data[i];
        data[i] = data[j];
        data[j] = temp;
    }
}

//
// HMac
//

HMac::HMac()
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	_ctx = calloc(1, sizeof(HMAC_CTX));
	HMAC_CTX_init((HMAC_CTX *)_ctx);
#else
	hmac = (void *)HMAC_CTX_new();
#endif
}

HMac::~HMac()
{
	if (_ctx) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
		HMAC_CTX_cleanup((HMAC_CTX *)_ctx);
		free(_ctx);
#else
		HMAC_CTX_free((HMAC_CTX *)_ctx);
#endif
		_ctx = NULL;
	}
}

bool HMac::init(const char *md, const void *key, int keylen)
{
	const EVP_MD* evp = EVP_get_digestbyname(md);

	if (!evp || !_ctx)
		return false;
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
	HMAC_Init_ex((HMAC_CTX *)_ctx, key, keylen, evp, NULL); /* no return value on OpenSSL 0.9.x */
	return true;
#else
	if (HMAC_Init_ex((HMAC_CTX *)_ctx, key, keylen, evp, NULL) == 1)
		return true;
#endif
	return false;
}

bool HMac::update(const void *input, size_t ilen)
{
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
	HMAC_Update((HMAC_CTX *)_ctx, input, ilen); /* no return value on OpenSSL 0.9.x */
	return true;
#else
	if (HMAC_Update((HMAC_CTX *)_ctx, (uint8_t *)input, ilen) == 1)
		return true;
#endif
	return false;
}

bool HMac::final(void *output, int olen)
{
#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
	HMAC_Final((HMAC_CTX *)_ctx, output, NULL); /* no return value on OpenSSL 0.9.x */
	return true;
#else
	if (HMAC_Final((HMAC_CTX *)_ctx, (uint8_t *)output, NULL) == 1)
		return true;
#endif
	return false;
}

bool HMac::HMAC(const char *md, const void *key, int keylen,
					const void *input, size_t ilen,
					void *output, int olen)
{
	HMac hmac;
	if (!hmac.init(md, key, keylen))
		return false;
	if (!hmac.update(input, ilen))
		return false;
	return hmac.final(output, olen);
}

//
// Digest
//
Digest::Digest()
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
	_ctx = (void *)EVP_MD_CTX_create();
#else
	_ctx = (void *)EVP_MD_CTX_new();
#endif
}

Digest::~Digest()
{
	if (_ctx) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_destroy((EVP_MD_CTX *)_ctx);
#else
		EVP_MD_CTX_free((EVP_MD_CTX *)_ctx);
#endif
		_ctx = NULL;
	}
}

bool Digest::init(const char *md)
{
	const EVP_MD *evp = EVP_get_digestbyname(md);

	if (!_ctx || !evp)
		return false;
	if (EVP_DigestInit_ex((EVP_MD_CTX *)_ctx, evp, NULL) != 1)
		return false;
	return true;
}

bool Digest::update(const uint8_t *input, int ilen)
{
	return (EVP_DigestUpdate((EVP_MD_CTX *)_ctx, input, ilen) == 1);
}

bool Digest::update(const string &input)
{
	return update((uint8_t *)input.data(), input.length());
}

bool Digest::final(uint8_t *output, int olen)
{
	return (EVP_DigestFinal_ex((EVP_MD_CTX *)_ctx, output, NULL) == 1);
}

bool Digest::digest(const char *md, const uint8_t *input, int ilen, uint8_t *output, int olen)
{
	Digest ctx;
	
	if (!ctx.init(md))
		return false;
	if(!ctx.update(input, ilen))
		return false;
	if (!ctx.final(output, olen))
		return false;
	return true;
}

bool Digest::MD4(const uint8_t *input, int ilen, uint8_t *output, int olen)
{
	return digest("md4", input, ilen, output, olen);
}

bool Digest::MD5(const uint8_t *input, int ilen, uint8_t *output, int olen)
{
	return digest("md5", input, ilen, output, olen);
}


//
// Rc4
//

Rc4::Rc4()
	: _ctx(NULL)
{}

Rc4::~Rc4()
{
	freeCtx();
}

bool Rc4::setup(const uint8_t *key, int keylen)
{
	freeCtx();

	if (!key || (keylen == 0))
		return false;
	if (!(_ctx = calloc(1, sizeof(RC4_KEY))))
		return false;
	RC4_set_key((RC4_KEY *)_ctx, keylen, key);
	return true;
}

bool Rc4::update(int length, const uint8_t *input, uint8_t *output)
{
	RC4((RC4_KEY *)_ctx, length, input, output);
	return true;
}

void Rc4::freeCtx()
{
	if (_ctx) {
		memset(_ctx, 0, sizeof(RC4_KEY));
		free(_ctx);
		_ctx = NULL;
	}
}

bool Rc4::rc4k(const uint8_t *key, int keylen, 
			   int length, const uint8_t *input, uint8_t *output)
{
	Rc4 rc4;
	if (!rc4.setup(key, keylen))
		return false;
	if (!rc4.update(length, input, output))
		return false;
	return true;
}

//
// Cipher
//

Cipher::Cipher()
{
	_ctx = (void *)EVP_CIPHER_CTX_new();
}

Cipher::~Cipher()
{
	if (_ctx) {
		EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)_ctx);
		_ctx = NULL;
	}
}

bool Cipher::init(const char *cipher, bool encrypt, const uint8_t *key, const uint8_t *iv)
{
	const EVP_CIPHER *evp = EVP_get_cipherbyname(cipher);
	EVP_CIPHER_CTX *octx = (EVP_CIPHER_CTX *)_ctx;
	int enc = encrypt ? 1 : 0;

	if (!_ctx || !evp)
		return false;
	if (EVP_CipherInit_ex(octx, evp, NULL, key, iv, enc) != 1)
		return false;
	EVP_CIPHER_CTX_set_padding(octx, 0);
	_ctx = (void *)octx;
	return true;
}

bool Cipher::update(const uint8_t *input, int ilen, uint8_t *output, int *olen)
{
	return (EVP_CipherUpdate((EVP_CIPHER_CTX *)_ctx, output, olen, input, ilen) == 1);
}

bool Cipher::final(uint8_t *output, int *olen)
{
	return (EVP_CipherFinal_ex((EVP_CIPHER_CTX *)_ctx, output, olen) == 1);
}
