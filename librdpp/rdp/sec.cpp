#include <rdp/sec.h>
#include <rdp/lic.h>
#include <rdp/t125/gcc.h>
#include <rdp/t125/mcs.h>
#include <rdp/tpkt.h>

#include <openssl/hmac.h>

#define TAG "SEC"

using namespace rdpp;

namespace rdpp {

	/// @summary: contain client random for basic security
    /// @see: http://msdn.microsoft.com/en-us/library/cc240472.aspx
    struct ClientSecurityExchangePDU {
        uint32_t length;    // sizeof(self) - 4
        Buffer encryptedClientRandom; // length = length - 8

        void read(Buffer *s)
        {
            length = s->readUInt32();
            s->retrieve(encryptedClientRandom, length - 8);
        }
        void write(Buffer *s)
        {
            s->appendUInt32(length);
            s->append(encryptedClientRandom);
        }
    };

	/* 0x36 repeated 40 times */
	static const uint8_t pad1[40] =
	{
		54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
		54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
		54, 54, 54, 54, 54, 54, 54, 54
	};

	/* 0x5C repeated 48 times */
	static const uint8_t pad2[48] =
	{
		92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
		92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
		92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92
	};

	static uint8_t fips_ivec[8] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

	static const uint8_t fips_reverse_table[256] =
	{
		0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
		0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
		0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
		0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
		0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
		0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
		0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
		0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
		0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
		0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
		0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
		0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
		0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
		0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
		0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
		0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
		0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
		0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
		0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
		0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
		0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
		0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
		0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
		0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
		0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
		0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
		0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
		0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
		0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
		0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
		0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
		0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff
	};

	static const uint8_t fips_oddparity_table[256] =
	{
		0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07,
		0x08, 0x08, 0x0b, 0x0b, 0x0d, 0x0d, 0x0e, 0x0e,
		0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
		0x19, 0x19, 0x1a, 0x1a, 0x1c, 0x1c, 0x1f, 0x1f,
		0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26,
		0x29, 0x29, 0x2a, 0x2a, 0x2c, 0x2c, 0x2f, 0x2f,
		0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37,
		0x38, 0x38, 0x3b, 0x3b, 0x3d, 0x3d, 0x3e, 0x3e,
		0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
		0x49, 0x49, 0x4a, 0x4a, 0x4c, 0x4c, 0x4f, 0x4f,
		0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57,
		0x58, 0x58, 0x5b, 0x5b, 0x5d, 0x5d, 0x5e, 0x5e,
		0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67,
		0x68, 0x68, 0x6b, 0x6b, 0x6d, 0x6d, 0x6e, 0x6e,
		0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
		0x79, 0x79, 0x7a, 0x7a, 0x7c, 0x7c, 0x7f, 0x7f,
		0x80, 0x80, 0x83, 0x83, 0x85, 0x85, 0x86, 0x86,
		0x89, 0x89, 0x8a, 0x8a, 0x8c, 0x8c, 0x8f, 0x8f,
		0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97,
		0x98, 0x98, 0x9b, 0x9b, 0x9d, 0x9d, 0x9e, 0x9e,
		0xa1, 0xa1, 0xa2, 0xa2, 0xa4, 0xa4, 0xa7, 0xa7,
		0xa8, 0xa8, 0xab, 0xab, 0xad, 0xad, 0xae, 0xae,
		0xb0, 0xb0, 0xb3, 0xb3, 0xb5, 0xb5, 0xb6, 0xb6,
		0xb9, 0xb9, 0xba, 0xba, 0xbc, 0xbc, 0xbf, 0xbf,
		0xc1, 0xc1, 0xc2, 0xc2, 0xc4, 0xc4, 0xc7, 0xc7,
		0xc8, 0xc8, 0xcb, 0xcb, 0xcd, 0xcd, 0xce, 0xce,
		0xd0, 0xd0, 0xd3, 0xd3, 0xd5, 0xd5, 0xd6, 0xd6,
		0xd9, 0xd9, 0xda, 0xda, 0xdc, 0xdc, 0xdf, 0xdf,
		0xe0, 0xe0, 0xe3, 0xe3, 0xe5, 0xe5, 0xe6, 0xe6,
		0xe9, 0xe9, 0xea, 0xea, 0xec, 0xec, 0xef, 0xef,
		0xf1, 0xf1, 0xf2, 0xf2, 0xf4, 0xf4, 0xf7, 0xf7,
		0xf8, 0xf8, 0xfb, 0xfb, 0xfd, 0xfd, 0xfe, 0xfe
	};

	static bool security_salted_hash(const uint8_t* salt, const uint8_t* input, int length,
		const uint8_t* salt1, const uint8_t* salt2, uint8_t* output)
	{
		Digest sha1;
		Digest md5;
		uint8_t sha1_digest[Digest::SHA1_LENGTH];

		/* SaltedHash(Salt, Input, Salt1, Salt2) = MD5(S + SHA1(Input + Salt + Salt1 + Salt2)) */

		/* SHA1_Digest = SHA1(Input + Salt + Salt1 + Salt2) */
		if (!sha1.init("sha1"))
			return false;
        if (!sha1.update(input, length)) /* Input */
			return false;
        if (!sha1.update(salt, 48)) /* Salt (48 bytes) */
			return false;
        if (!sha1.update(salt1, 32)) /* Salt1 (32 bytes) */
			return false;
        if (!sha1.update(salt2, 32)) /* Salt2 (32 bytes) */
			return false;
        if (!sha1.final(sha1_digest, sizeof(sha1_digest)))
			return false;

		/* SaltedHash(Salt, Input, Salt1, Salt2) = MD5(S + SHA1_Digest) */
		if (!md5.init("md5"))
			return false;
        if (!md5.update(salt, 48)) /* Salt (48 bytes) */
			return false;
        if (!md5.update(sha1_digest, sizeof(sha1_digest))) /* SHA1_Digest */
			return false;
        if (!md5.final(output, Digest::MD5_DIGEST_LENGTH))
			return false;
		return true;
	}

	static bool security_premaster_hash(const char* input, int length, const uint8_t* premaster_secret,
		const uint8_t* client_random, const uint8_t* server_random, uint8_t* output)
	{
		/* PremasterHash(Input) = SaltedHash(PremasterSecret, Input, ClientRandom, ServerRandom) */
		return security_salted_hash(premaster_secret, (uint8_t*)input, length, client_random, server_random, output);
	}

	bool security_master_secret(const uint8_t* premaster_secret, const uint8_t* client_random,
		const uint8_t* server_random, uint8_t* output)
	{
		/* MasterSecret = PremasterHash('A') + PremasterHash('BB') + PremasterHash('CCC') */
	return security_premaster_hash("A", 1, premaster_secret, client_random, server_random, &output[0]) &&
		security_premaster_hash("BB", 2, premaster_secret, client_random, server_random, &output[16]) &&
		security_premaster_hash("CCC", 3, premaster_secret, client_random, server_random, &output[32]);
	}

	static bool security_master_hash(const char* input, int length, const uint8_t* master_secret,
		const uint8_t* client_random, const uint8_t* server_random, uint8_t* output)
	{
		/* MasterHash(Input) = SaltedHash(MasterSecret, Input, ServerRandom, ClientRandom) */
		return security_salted_hash(master_secret, (const uint8_t*)input, length, server_random, client_random, output);
	}

	bool security_session_key_blob(const uint8_t* master_secret, const uint8_t* client_random,
			const uint8_t* server_random, uint8_t* output)
	{
		/* MasterHash = MasterHash('A') + MasterHash('BB') + MasterHash('CCC') */
	return security_master_hash("A", 1, master_secret, client_random, server_random, &output[0]) &&
		security_master_hash("BB", 2, master_secret, client_random, server_random, &output[16]) &&
		security_master_hash("CCC", 3, master_secret, client_random, server_random, &output[32]);
	}

	void security_mac_salt_key(const uint8_t* session_key_blob, const uint8_t* client_random,
		const uint8_t* server_random, uint8_t* output)
	{
		/* MacSaltKey = First128Bits(SessionKeyBlob) */
		memcpy(output, session_key_blob, 16);
	}
	
	bool security_md5_16_32_32(const uint8_t* in0, const uint8_t* in1, const uint8_t* in2, uint8_t* output)
	{
		Digest md5;

		if (!md5.init("md5"))
			return false;
		if (!md5.update( in0, 16))
			return false;
		if (!md5.update( in1, 32))
			return false;
		if (!md5.update( in2, 32))
			return false;
		if (!md5.final(output, Digest::MD5_DIGEST_LENGTH))
			return false;
		return true;
	}

	bool security_licensing_encryption_key(const uint8_t* session_key_blob, const uint8_t* client_random,
		const uint8_t* server_random, uint8_t* output)
	{
		/* LicensingEncryptionKey = MD5(Second128Bits(SessionKeyBlob) + ClientRandom + ServerRandom)) */
		return security_md5_16_32_32(&session_key_blob[16], client_random, server_random, output);
	}

	bool security_mac_data(const uint8_t* mac_salt_key, const uint8_t* data, uint8_t length,
		uint8_t* output)
	{
		Digest sha1;
		Digest md5;
		uint8_t length_le[4];
		uint8_t sha1_digest[Digest::SHA1_LENGTH];

		/* MacData = MD5(MacSaltKey + pad2 + SHA1(MacSaltKey + pad1 + length + data)) */

		security_uint32_le(length_le, length); /* length must be little-endian */

		/* SHA1_Digest = SHA1(MacSaltKey + pad1 + length + data) */
		if (!sha1.init("sha1"))
			return false;
		if (!sha1.update(mac_salt_key, 16)) /* MacSaltKey */
			return false;
		if (!sha1.update(pad1, sizeof(pad1))) /* pad1 */
			return false;
		if (!sha1.update(length_le, sizeof(length_le))) /* length */
			return false;
		if (!sha1.update(data, length)) /* data */
			return false;
		if (!sha1.final(sha1_digest, sizeof(sha1_digest)))
			return false;

		/* MacData = MD5(MacSaltKey + pad2 + SHA1_Digest) */
		if (!md5.init("md5"))
			return false;
		if (!md5.update( mac_salt_key, 16)) /* MacSaltKey */
			return false;
		if (!md5.update( pad2, sizeof(pad2))) /* pad2 */
			return false;
		if (!md5.update( sha1_digest, sizeof(sha1_digest))) /* SHA1_Digest */
			return false;
		if (!md5.final(output, Digest::MD5_DIGEST_LENGTH))
			return false;
		return true;
	}

	static bool security_A(uint8_t* master_secret, const uint8_t* client_random, const uint8_t* server_random,
		uint8_t* output)
	{
		return
			security_premaster_hash("A", 1, master_secret, client_random, server_random, &output[0]) &&
			security_premaster_hash("BB", 2, master_secret, client_random, server_random, &output[16]) &&
			security_premaster_hash("CCC", 3, master_secret, client_random, server_random, &output[32]);
	}

	static bool security_X(uint8_t* master_secret, const uint8_t* client_random, const uint8_t* server_random,
			uint8_t* output)
	{
		return
			security_premaster_hash("X", 1, master_secret, client_random, server_random, &output[0]) &&
			security_premaster_hash("YY", 2, master_secret, client_random, server_random, &output[16]) &&
			security_premaster_hash("ZZZ", 3, master_secret, client_random, server_random, &output[32]);
	}

	static void fips_expand_key_bits(uint8_t *in, uint8_t *out)
	{
		uint8_t buf[21], c;
		int i, b, p, r;

		/* reverse every byte in the key */
		for (i = 0; i < 21; i++)
			buf[i] = fips_reverse_table[in[i]];

		/* insert a zero-bit after every 7th bit */
		for (i = 0, b = 0; i < 24; i++, b += 7) {
			p = b / 8;
			r = b % 8;
			if (r == 0) {
				out[i] = buf[p] & 0xfe;
			} else {
				/* c is accumulator */
				c = buf[p] << r;
				c |= buf[p + 1] >> (8 - r);
				out[i] = c & 0xfe;
			}
		}

		/* reverse every byte */
		/* alter lsb so the byte has odd parity */
		for (i = 0; i < 24; i++)
			out[i] = fips_oddparity_table[fips_reverse_table[out[i]]];
	}

} // namespace rdpp

using namespace rdpp;

//
// SecLayer
//

SecLayer::SecLayer(Layer *presentation, FastPathLayer *fastPathListener, bool serverMode)
    : Layer(presentation)
    , FastPathLayer(fastPathListener)
	, _serverMode(serverMode)
    , _enableEncryption(false), _enableSecureCheckSum(false)
{
	_decrypt_use_count = 0;
	_decrypt_checksum_use_count = 0;
	_encrypt_use_count = 0;
	_encrypt_checksum_use_count = 0;

	memset(&_sign_key, 0, sizeof(_sign_key));
	memset(&_decrypt_key, 0, sizeof(_decrypt_key));
	memset(&_encrypt_key, 0, sizeof(_encrypt_key));
	memset(&_decrypt_update_key, 0, sizeof(_decrypt_update_key));
	memset(&_encrypt_update_key, 0, sizeof(_encrypt_update_key));
	_rc4_key_len = 0;

	memset(&_fips_sign_key, 0, sizeof(_fips_sign_key));
	memset(&_fips_encrypt_key, 0, sizeof(_fips_encrypt_key));
	memset(&_fips_decrypt_key, 0, sizeof(_fips_decrypt_key));
}

void SecLayer::init()
{
    if (getGCCServerSettings().core.rdpVersion == RDP_VERSION_5_PLUS)
        _info.extendedInfo = rdpp::make_shared<RDPExtendedInfo>();
}

bool SecLayer::security_mac_signature(const uint8_t* data, uint32_t length, uint8_t* output)
{
	Digest sha1;
	Digest md5;
	uint8_t length_le[4];
	uint8_t md5_digest[Digest::MD5_DIGEST_LENGTH];
	uint8_t sha1_digest[Digest::SHA1_LENGTH];

	security_uint32_le(length_le, length); /* length must be little-endian */

	/* SHA1_Digest = SHA1(MACKeyN + pad1 + length + data) */
	if (!sha1.init("sha1"))
		return false;
	if (!sha1.update(_sign_key, _rc4_key_len)) /* MacKeyN */
		return false;
	if (!sha1.update(pad1, sizeof(pad1))) /* pad1 */
		return false;
	if (!sha1.update(length_le, sizeof(length_le))) /* length */
		return false;
	if (!sha1.update(data, length)) /* data */
		return false;
	if (!sha1.final(sha1_digest, sizeof(sha1_digest)))
		return false;

	/* MACSignature = First64Bits(MD5(MACKeyN + pad2 + SHA1_Digest)) */
	if (!md5.init("md5"))
		return false;
	if (!md5.update( _sign_key, _rc4_key_len)) /* MacKeyN */
		return false;
	if (!md5.update( pad2, sizeof(pad2)))/* pad2 */
		return false;
	if (!md5.update( sha1_digest, sizeof(sha1_digest))) /* SHA1_Digest */
		return false;
	if (!md5.final(md5_digest, sizeof(md5_digest)))
		return false;

	memcpy(output, md5_digest, 8);
	return true;
}

bool SecLayer::security_salted_mac_signature(const uint8_t* data, uint32_t length, bool encryption, uint8_t* output)
{
	Digest sha1;
	Digest md5;
	uint8_t length_le[4];
	uint8_t use_count_le[4];
	uint8_t md5_digest[Digest::MD5_DIGEST_LENGTH];
	uint8_t sha1_digest[Digest::SHA1_LENGTH];

	security_uint32_le(length_le, length); /* length must be little-endian */

	if (encryption) {
		security_uint32_le(use_count_le, _encrypt_checksum_use_count);
	} else {
		// We calculate checksum on plain text, so we must have already
		// decrypt it, which means decrypt_checksum_use_count is off by one.
		security_uint32_le(use_count_le, _decrypt_checksum_use_count - 1);
	}

	/* SHA1_Digest = SHA1(MACKeyN + pad1 + length + data) */
	if (!sha1.init("sha1"))
		return false;
	if (!sha1.update(_sign_key, _rc4_key_len)) /* MacKeyN */
		return false;
	if (!sha1.update(pad1, sizeof(pad1))) /* pad1 */
		return false;
	if (!sha1.update(length_le, sizeof(length_le))) /* length */
		return false;
	if (!sha1.update(data, length)) /* data */
		return false;
	if (!sha1.update(use_count_le, sizeof(use_count_le))) /* encryptionCount */
		return false;
	if (!sha1.final(sha1_digest, sizeof(sha1_digest)))
		return false;

	/* MACSignature = First64Bits(MD5(MACKeyN + pad2 + SHA1_Digest)) */
	if (!md5.init("md5"))
		return false;
	if (!md5.update( _sign_key, _rc4_key_len)) /* MacKeyN */
		return false;
	if (!md5.update( pad2, sizeof(pad2))) /* pad2 */
		return false;
	if (!md5.update( sha1_digest, sizeof(sha1_digest))) /* SHA1_Digest */
		return false;
	if (!md5.final(md5_digest, sizeof(md5_digest)))
		return false;

	memcpy(output, md5_digest, 8);
	return true;
}

bool SecLayer::security_establish_keys(const uint8_t* client_random, const uint8_t* server_random)
{
	uint8_t pre_master_secret[48];
	uint8_t master_secret[48];
	uint8_t session_key_blob[48];
	uint8_t salt[] = { 0xD1, 0x26, 0x9E }; /* 40 bits: 3 bytes, 56 bits: 1 byte */

	if (_encryptionMethods == ENCRYPTION_METHOD_FIPS) {
		Digest sha1;
		uint8_t client_encrypt_key_t[Digest::SHA1_LENGTH + 1];
		uint8_t client_decrypt_key_t[Digest::SHA1_LENGTH + 1];
			
		if (!sha1.init("sha1"))
			return false;
		if (!sha1.update(client_random + 16, 16))
			return false;
		if (!sha1.update(server_random + 16, 16))
			return false;
		if (!sha1.final(client_encrypt_key_t, sizeof(client_encrypt_key_t)))
			return false;

		client_encrypt_key_t[20] = client_encrypt_key_t[0];

		if (!sha1.init("sha1"))
			return false;
		if (!sha1.update(client_random, 16))
			return false;
		if (!sha1.update(server_random, 16))
			return false;
		if (!sha1.final(client_decrypt_key_t, sizeof(client_decrypt_key_t)))
			return false;
		client_decrypt_key_t[20] = client_decrypt_key_t[0];

		if (!sha1.init("sha1"))
			return false;
		if (!sha1.update(client_decrypt_key_t, Digest::SHA1_LENGTH))
			return false;
		if (!sha1.update(client_encrypt_key_t, Digest::SHA1_LENGTH))
			return false;
		sha1.final(_fips_sign_key, sizeof(_fips_sign_key));

		if (_serverMode) {
			fips_expand_key_bits(client_encrypt_key_t, _fips_decrypt_key);
			fips_expand_key_bits(client_decrypt_key_t, _fips_encrypt_key);
		} else {
			fips_expand_key_bits(client_encrypt_key_t, _fips_encrypt_key);
			fips_expand_key_bits(client_decrypt_key_t, _fips_decrypt_key);
		}
	}

	memcpy(pre_master_secret, client_random, 24);
	memcpy(pre_master_secret + 24, server_random, 24);

	security_A(pre_master_secret, client_random, server_random, master_secret);
	security_X(master_secret, client_random, server_random, session_key_blob);

	memcpy(_sign_key, session_key_blob, 16);

	if (_serverMode) {
		security_md5_16_32_32(&session_key_blob[16], client_random, server_random, _encrypt_key);
		security_md5_16_32_32(&session_key_blob[32], client_random, server_random, _decrypt_key);
	} else {
		security_md5_16_32_32(&session_key_blob[16], client_random, server_random, _decrypt_key);
		security_md5_16_32_32(&session_key_blob[32], client_random, server_random, _encrypt_key);
	}

	if (_encryptionMethods == ENCRYPTION_METHOD_40BIT) {
		memcpy(_sign_key, salt, 3);
		memcpy(_decrypt_key, salt, 3);
		memcpy(_encrypt_key, salt, 3);
		_rc4_key_len = 8;
	} else if (_encryptionMethods == ENCRYPTION_METHOD_56BIT) {
		memcpy(_sign_key, salt, 1);
		memcpy(_decrypt_key, salt, 1);
		memcpy(_encrypt_key, salt, 1);
		_rc4_key_len = 8;
	} else if (_encryptionMethods == ENCRYPTION_METHOD_128BIT) {
		_rc4_key_len = 16;
	}

	memcpy(_decrypt_update_key, _decrypt_key, 16);
	memcpy(_encrypt_update_key, _encrypt_key, 16);
	_decrypt_use_count = 0;
	_decrypt_checksum_use_count = 0;
	_encrypt_use_count = 0;
	_encrypt_checksum_use_count = 0;
	return true;
}

bool SecLayer::security_key_update(uint8_t* key, uint8_t* update_key, int key_len)
{
	uint8_t sha1h[Digest::SHA1_LENGTH];
	Digest sha1;
	Digest md5;
	Rc4 rc4;
	uint8_t salt[] = { 0xD1, 0x26, 0x9E }; /* 40 bits: 3 bytes, 56 bits: 1 byte */

	if (!sha1.init("sha1"))
		return false;
    if (!sha1.update(update_key, key_len))
		return false;
    if (!sha1.update(pad1, sizeof(pad1)))
		return false;
    if (!sha1.update(key, key_len))
		return false;
    if (!sha1.final(sha1h, sizeof(sha1h)))
		return false;

	if (!md5.init("md5"))
		return false;
    if (!md5.update( update_key, key_len))
		return false;
    if (!md5.update( pad2, sizeof(pad2)))
		return false;
    if (!md5.update( sha1h, sizeof(sha1h)))
		return false;
    if (!md5.final(key, Digest::MD5_DIGEST_LENGTH))
		return false;

	if (!rc4.setup(key, key_len))
		return false;
	if (!rc4.update(key_len, key, key))
		return false;

	if (_encryptionMethods == ENCRYPTION_METHOD_40BIT) {
		memcpy(key, salt, 3);
	} else if (_encryptionMethods == ENCRYPTION_METHOD_56BIT) {
		memcpy(key, salt, 1);
	}
	return true;
}

bool SecLayer::security_encrypt(uint8_t* data, int length)
{
	if (_encrypt_use_count >= 4096) {
		if (!security_key_update(_encrypt_key, _encrypt_update_key, _rc4_key_len))
			return false;
		if (!_rc4_encrypt_key.setup(_encrypt_key, _rc4_key_len))
			return false;
		_encrypt_use_count = 0;
		RDPP_LOG(TAG, DEBUG) << "Update Encrypt Key " << hexdump(_encrypt_key, 16);
	}
	if (!_rc4_encrypt_key.update(length, data, data))
		return false;
	_encrypt_use_count++;
	_encrypt_checksum_use_count++;
	return true;
}

bool SecLayer::security_decrypt(uint8_t* data, int length)
{
	if (_decrypt_use_count >= 4096) {
		if (!security_key_update(_decrypt_key, _decrypt_update_key, _rc4_key_len))
			return false;
		if (!_rc4_decrypt_key.setup(_decrypt_key, _rc4_key_len))
			return false;
		_decrypt_use_count = 0;
		RDPP_LOG(TAG, DEBUG) << "Update Decrypt Key " << hexdump(_decrypt_key, 16);
	}
	if (!_rc4_decrypt_key.update(length, data, data))
		return false;
	_decrypt_use_count += 1;
	_decrypt_checksum_use_count++;
	return true;
}

bool SecLayer::security_hmac_signature(const uint8_t* data, int length, uint8_t* output)
{
	uint8_t buf[Digest::SHA1_LENGTH];
	uint8_t use_count_le[4];
	HMac hmac;

	security_uint32_le(use_count_le, _encrypt_use_count);

	if (!hmac.init("sha1", _fips_sign_key, Digest::SHA1_LENGTH))
		return false;
	if (!hmac.update(data, length))
		return false;
	if (!hmac.update(use_count_le, 4))
		return false;
	if (!hmac.final(buf, Digest::SHA1_LENGTH))
		return false;

	memmove(output, buf, 8);
	return true;
}

bool SecLayer::security_fips_encrypt(uint8_t* data, int length)
{
	int olen;
	if (_fips_encrypt.update(data, length, data, &olen))
		return false;
	_encrypt_use_count++;
	return true;
}

bool SecLayer::security_fips_decrypt(uint8_t* data, int length)
{
	int olen;
	if (!_fips_decrypt.update(data, length, data, &olen))
		return false;
	return true;
}

bool SecLayer::security_fips_check_signature(const uint8_t* data, int length, const uint8_t* sig)
{
	uint8_t buf[Digest::SHA1_LENGTH];
	uint8_t use_count_le[4];
	HMac hmac;

	security_uint32_le(use_count_le, _decrypt_use_count);

	if (!hmac.init("sha1", _fips_sign_key, Digest::SHA1_LENGTH))
		return false;
	if (!hmac.update(data, length))
		return false;
	if (!hmac.update(use_count_le, 4))
		return false;
	if (!hmac.final(buf, Digest::SHA1_LENGTH))
		return false;

	_decrypt_use_count++;

	return (!memcmp(sig, buf, 8));
}

bool SecLayer::encrypt(Buffer *s, bool saltedMacGeneration)
{
	bool status;
	uint8_t sig[8];

	if (_encryptionMethods == ENCRYPTION_METHOD_FIPS) {
		uint8_t pad;

		if ((pad = 8 - (s->length() % 8)) == 8)
			pad = 0;
		if (!security_hmac_signature(s->data(), s->length(), sig))
			return false;
		if (pad)
			s->append(pad, '\0');
		if (!security_fips_encrypt(s->data(), s->length()))
			return false;

		s->prepend(sig, 8);
		s->prependUInt8(pad); // padding
		s->prependUInt8(0x1); // TSFIPS_VERSION 1
		s->prependUInt16(0x10); // length
		return true;
	}
		
	if (saltedMacGeneration)
		status = security_salted_mac_signature(s->data(), s->length(), true, sig);
	else
		status = security_mac_signature(s->data(), s->length(), sig);

	if (!status || !security_encrypt(s->data(), s->length()))
		return false;

	s->prepend(sig, 8);
	return true;
}

bool SecLayer::decrypt(Buffer *s, bool saltedMacGeneration)
{
	uint8_t cmac[8];
	uint8_t wmac[8];
	bool status;

	if (_encryptionMethods == ENCRYPTION_METHOD_FIPS) {
		uint16_t len;
		uint8_t version, pad;
		uint8_t *sig;

		if (s->length() < 12)
			return false;

		len = s->readUInt16(); // 0x10
		version = s->readUInt8(); // 0x1
		pad = s->readUInt8();

		sig = s->data();
		s->retrieve(8); // signature

		if (!security_fips_decrypt(s->data(), s->length())) {
			RDPP_LOG(TAG, ERROR) << "cannot decrypt";
			return false;
		}

		if (!security_fips_check_signature(s->data(), s->length() - pad, sig)) {
			RDPP_LOG(TAG, ERROR) << "invalid packet signature";
			return false;
		}
		s->unwrite(pad);
		return true;
	}

	s->retrieve(wmac, sizeof(wmac));

	if (!security_decrypt(s->data(), s->length())) {
		RDPP_LOG(TAG, ERROR) << "cannot decrypt";
		return false;
	}

	if (saltedMacGeneration)
		status = security_salted_mac_signature(s->data(), s->length(), false, cmac);
	else
		status = security_mac_signature(s->data(), s->length(), cmac);

	if (!status)
		return false;

	if (memcmp(wmac, cmac, sizeof(wmac)) != 0) {
		RDPP_LOG(TAG, WARN) << "invalid packet signature";
		return false;
	}
	return true;
}

void SecLayer::dataReceived(Buffer *data)
{
    if (!_enableEncryption) {
        _presentation->recv(data);
		return;
	}
    uint16_t securityFlag = data->readUInt16();
    uint16_t securityFlagHi = data->readUInt16();

    if (securityFlag & SEC_ENCRYPT) {
		if (!decrypt(data, (securityFlag & SEC_SECURE_CHECKSUM) ? true : false)) {
			RDPP_LOG(TAG, ERROR) << "decrypt error";
			close();
			return;
		}
	}
    _presentation->recv(data);
}

void SecLayer::send(Buffer *data)
{
    if (!_enableEncryption) {
        _transport->send(data);
        return;
    }

    uint16_t flag = SEC_ENCRYPT;
    if (_enableSecureCheckSum)
        flag |= SEC_SECURE_CHECKSUM;
    sendFlagged(flag, data);
}

void SecLayer::sendFlagged(uint16_t flag, Buffer *data)
{
	if (flag & SEC_ENCRYPT) {
		if (!encrypt(data, (flag & SEC_SECURE_CHECKSUM) ? true : false)) {
			RDPP_LOG(TAG, ERROR) << "encrypt error";
			return;
		}
	}

    // Basic Security Header 
	data->prependUInt16(0); // pad
    data->prependUInt16(flag);
    _transport->send(data);
}

void SecLayer::recvFastPath(uint16_t secFlag, Buffer *s)
{
	//RDPP_LOG(TAG, TRACE) << "SecLayer::recvFastPath(secFlag:" << (void *)secFlag << ", " << s->length() << " Bytes)";

	if (_enableEncryption && (secFlag & FASTPATH_OUTPUT_ENCRYPTED)) {
		if (!decrypt(s, (secFlag & FASTPATH_OUTPUT_SECURE_CHECKSUM))) {
			RDPP_LOG(TAG, ERROR) << "decrypt error";
			return;
		}
	}

    _fastPathListener->recvFastPath(secFlag, s);
}

void SecLayer::sendFastPath(uint16_t secFlag, Buffer *data)
{
	if (_enableEncryption) {
        secFlag |= FASTPATH_OUTPUT_ENCRYPTED;
		if (_enableSecureCheckSum)
			secFlag |= FASTPATH_OUTPUT_SECURE_CHECKSUM;
		if (!encrypt(data, _enableSecureCheckSum)) {
			return;
		}
	}

	//RDPP_LOG(TAG, TRACE) << "SecLayer::sendFastPath(secFlag=" << (void *)secFlag << ", " << data->length() << " Bytes)";	
    _fastPathSender->sendFastPath(secFlag, data);
}

uint16_t SecLayer::getUserId()
{
    return transport()->getUserId();
}

uint16_t SecLayer::getChannelId()
{
    return transport()->getChannelId();
}

ClientSettings &SecLayer::getGCCClientSettings()
{
    return transport()->getGCCClientSettings();
}

ServerSettings &SecLayer::getGCCServerSettings()
{
    return transport()->getGCCServerSettings();
}

MCSProxySender *SecLayer::transport()
{
    return dynamic_cast<MCSProxySender *>(_transport);
}

//
// ClientSecLayer
//

ClientSecLayer::ClientSecLayer(Layer *presentation, FastPathLayer *fastPathListener)
    : SecLayer(presentation, fastPathListener, false)
{
    _licenceManager = rdpp::make_shared<LicenseManager>(this);
}

void ClientSecLayer::connect()
{
    _enableEncryption = (getGCCClientSettings().core.serverSelectedProtocol == 0);
	_encryptionMethods = getGCCServerSettings().security.encryptionMethod;

    if (_enableEncryption)
        sendClientRandom();

    sendInfoPkt();
}
void ClientSecLayer::sendInfoPkt()
{
    uint16_t secFlag = SEC_INFO_PKT;
    if (_enableEncryption)
        secFlag |= SEC_ENCRYPT;

    Buffer infoS;
    _info.write(&infoS);

	RDPP_LOG(TAG, TRACE) << "ClientSecLayer::sendInfoPkt(" << infoS.length() << " Bytes)";
    sendFlagged(secFlag, &infoS);

    setNextState(rdpp::bind(&ClientSecLayer::recvLicenceInfo, this, _1));
}

void ClientSecLayer::sendClientRandom()
{
	Buffer clientRandom;
	ClientSecurityExchangePDU message;
    Buffer messageS;

	// get and verify server certificate
    if (!getGCCServerSettings().security.serverCertificate.verify()) {
        RDPP_LOG(TAG, ERROR) << "cannot verify server identity";
		goto end;
    }
	getGCCServerSettings().security.serverCertificate.getPublicKey(_pubKeyN, _pubKeyE);

	// send crypt client random to server
	// client random must be (bitlen / 8) + 8 - see [MS-RDPBCGR] 5.3.4.1 for details
    message.length = _pubKeyN.length() + 8;
	message.encryptedClientRandom.resize(message.length);

	Rsa::random(clientRandom, CLIENT_RANDOM_LENGTH);
	Rsa::public_encrypt(clientRandom.data(), CLIENT_RANDOM_LENGTH,
						_pubKeyN.length(), _pubKeyN.data(), _pubKeyE.data(),
						message.encryptedClientRandom.data());

    message.write(&messageS);

	RDPP_LOG(TAG, ERROR) << "ClientSecLayer::sendClientRandom(" << messageS.length() << " Bytes)";
    sendFlagged(SEC_EXCHANGE_PKT, &messageS);

	Buffer &serverRandom(getGCCServerSettings().security.serverRandom);

	RDPP_LOG(TAG, TRACE) << " clientRandom " << hexdump(clientRandom);
	RDPP_LOG(TAG, TRACE) << " serverRandom " << hexdump(serverRandom);
	
	// now calculate encrypt / decrypt and update keys

	if (!security_establish_keys(clientRandom.data(), serverRandom.data())) {
		RDPP_LOG(TAG, ERROR) << "client establish keys failed";
		goto end;
	}

	if (_encryptionMethods == ENCRYPTION_METHOD_FIPS) {
		if (!_fips_encrypt.init("des-ede3-cbc", true, _fips_encrypt_key, fips_ivec)) {
			RDPP_LOG(TAG, ERROR) << "unable to init des3 encrypt key";
			goto end;
		}
		if (!_fips_decrypt.init("des-ede3-cbc", false, _fips_decrypt_key, fips_ivec)) {
			RDPP_LOG(TAG, ERROR) << "unable to init des3 decrypt key";
			goto end;
		}
	}

	if (!_rc4_decrypt_key.setup(_decrypt_key, _rc4_key_len) ||
			!_rc4_encrypt_key.setup(_encrypt_key, _rc4_key_len)) {
		RDPP_LOG(TAG, ERROR) << "unable to allocate rc4 key";
		goto end;
	}
	return;
end:
	close();
	return;
}

void ClientSecLayer::recvLicenceInfo(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "ClientSecLayer::recvLicenceInfo(" << data->length() << " Bytes)";

    uint16_t securityFlag = data->readUInt16();
    uint16_t securityFlagHi = data->readUInt16();

    if (!(securityFlag & SEC_LICENSE_PKT)) {
        RDPP_LOG(TAG, ERROR) << "waiting license packet";
        return;
    }

    if (_licenceManager->recv(data)) {
		setNextState(rdpp::bind(&ClientSecLayer::dataReceived, this, _1));
        // end of connection step of
        _presentation->connect();
    }
}

//
// ServerSecLayer
//

ServerSecLayer::ServerSecLayer(Layer *presentation, FastPathLayer *fastPathListener)
    : SecLayer(presentation, fastPathListener, true)
{
	if (!Rsa::generateKey(_rsaN, _rsaE, _rsaD)) {
		RDPP_LOG(TAG, ERROR) << "generate RSA keypair error";
	}
}

void ServerSecLayer::connect()
{
	RDPP_LOG(TAG, TRACE) << "ServerSecLayer::connect()";

    _enableEncryption = (getGCCClientSettings().core.serverSelectedProtocol == 0);
	_encryptionMethods = getGCCServerSettings().security.encryptionMethod;

    if (_enableEncryption)
        setNextState(rdpp::bind(&ServerSecLayer::recvClientRandom, this, _1));
    else
        setNextState(rdpp::bind(&ServerSecLayer::recvInfoPkt, this, _1));
}

bool ServerSecLayer::getCertificate(ServerCertificate &certificate)
{    
    RSAPublicKey &pkey = certificate.proprietary.PublicKeyBlob;

    pkey.modulus = _rsaN;
    memcpy(pkey.pubExp, _rsaE.data(), 4);
    pkey.keylen = pkey.modulus.length() + sizeof(pkey.padding);
    pkey.bitlen = (pkey.keylen - 8) * 8;
    pkey.datalen = (pkey.bitlen / 8) - 1;    

	certificate.dwVersion = CERT_CHAIN_VERSION_1;
    certificate.proprietary.wPublicKeyBlobLen = pkey.size();
	return certificate.proprietary.sign();
}

void ServerSecLayer::recvClientRandom(Buffer *s)
{
	ClientSecurityExchangePDU message;
	Buffer &serverRandom(getGCCServerSettings().security.serverRandom);
    Buffer clientRandom(_rsaN.length());

	RDPP_LOG(TAG, TRACE) << "ServerSecLayer::recvClientRandom(" << s->length() << " Bytes)";

    uint16_t securityFlag = s->readUInt16();
    uint16_t securityFlagHi = s->readUInt16();

    if (!(securityFlag & SEC_EXCHANGE_PKT)) {
        RDPP_LOG(TAG, ERROR) << "waiting client random";
        goto end;
    }

    if (securityFlag & SEC_ENCRYPT) {
		if (decrypt(s, (securityFlag & SEC_SECURE_CHECKSUM) ? true : false)) {
			RDPP_LOG(TAG, ERROR) << "decrypt error";
			goto end;
		}
	}

    message.read(s);
	
    Rsa::private_decrypt(message.encryptedClientRandom.data(), message.length - 8,
                         _rsaN.length(), _rsaN.data(), _rsaD.data(), clientRandom.beginWrite());
	clientRandom.hasWritten(32);

	if (!security_establish_keys(clientRandom.data(), serverRandom.data()))
		goto end;

	if (_encryptionMethods == ENCRYPTION_METHOD_FIPS) {
		if (!_fips_encrypt.init("des-ede3-cbc", true, _fips_encrypt_key, fips_ivec)) {
			RDPP_LOG(TAG, ERROR) << "unable to init des3 encrypt key";
			goto end;
		}
		if (!_fips_decrypt.init("des-ede3-cbc", false, _fips_decrypt_key, fips_ivec)) {
			RDPP_LOG(TAG, ERROR) << "unable to init des3 decrypt key";
			goto end;
		}
	}

	if (!_rc4_decrypt_key.setup(_decrypt_key, _rc4_key_len) ||
			!_rc4_encrypt_key.setup(_encrypt_key, _rc4_key_len)) {
		RDPP_LOG(TAG, ERROR) << "unable to allocate rc4 key";
		goto end;
	}

    setNextState(rdpp::bind(&ServerSecLayer::recvInfoPkt, this, _1));
	return;
end:
	close();
	return;
}

void ServerSecLayer::recvInfoPkt(Buffer *s)
{
	RDPP_LOG(TAG, TRACE) << "ServerSecLayer::recvInfoPkt(" << s->length() << " Bytes)";

    uint16_t securityFlag = s->readUInt16();
    uint16_t securityFlagHi = s->readUInt16();

    if (!(securityFlag & SEC_INFO_PKT)) {
        RDPP_LOG(TAG, ERROR) << "Waiting info packet";
        return;
    }

	if (securityFlag & SEC_ENCRYPT) {
		if (!decrypt(s, (securityFlag & SEC_SECURE_CHECKSUM) ? true : false)) {
			RDPP_LOG(TAG, ERROR) << "decrypt error";
			return;
		}
	}

    _info.read(s);
    // next state send error license
    sendLicensingErrorMessage();
    // reinit state
	setNextState(rdpp::bind(&ServerSecLayer::dataReceived, this, _1));
    _presentation->connect();
}

void ServerSecLayer::sendLicensingErrorMessage()
{
    Buffer s;
    createValidClientLicensingErrorMessage(&s);
	RDPP_LOG(TAG, TRACE) << "ServerSecLayer::sendLicensingErrorMessage(" << s.length() << " Bytes)";
    sendFlagged(SEC_LICENSE_PKT, &s);
}
