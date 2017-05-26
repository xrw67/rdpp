#include <rdp/t125/certificate.h>
#include <core/ber.h>

#define TAG "CERTIFICATE"

using namespace rdpp;

static const uint8_t initial_signature[] =
{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
};

// Terminal Services Signing Keys.
// Yes, Terminal Services Private Key is publicly available.
// http ://msdn.microsoft.com/en-us/library/cc240776.aspx

static const unsigned char tssk_modulus[] =
{
    0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9,
    0x4d, 0xbb, 0xc1, 0x1e, 0x4a, 0xba, 0x5f, 0xcb,
    0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5, 0xc1, 0xe2,
    0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95,
    0xce, 0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef,
    0x7c, 0xe7, 0xbf, 0xfe, 0x3d, 0xf6, 0x5c, 0x7d,
    0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61, 0xbb,
    0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87
};

static const unsigned char tssk_privateExponent[] =
{
    0x87, 0xa7, 0x19, 0x32, 0xda, 0x11, 0x87, 0x55,
    0x58, 0x00, 0x16, 0x16, 0x25, 0x65, 0x68, 0xf8,
    0x24, 0x3e, 0xe6, 0xfa, 0xe9, 0x67, 0x49, 0x94,
    0xcf, 0x92, 0xcc, 0x33, 0x99, 0xe8, 0x08, 0x60,
    0x17, 0x9a, 0x12, 0x9f, 0x24, 0xdd, 0xb1, 0x24,
    0x99, 0xc7, 0x3a, 0xb8, 0x0a, 0x7b, 0x0d, 0xdd,
    0x35, 0x07, 0x79, 0x17, 0x0b, 0x51, 0x9b, 0xb3,
    0xc7, 0x10, 0x01, 0x13, 0xe7, 0x3f, 0xf3, 0x5f
};

static const unsigned char tssk_exponent[] =
{
    0x5b, 0x7b, 0x88, 0xc0
};

static const char* certificate_read_errors[] =
{
	"Certificate tag",
	"TBSCertificate",
	"Explicit Contextual Tag [0]",
	"version",
	"CertificateSerialNumber",
	"AlgorithmIdentifier",
	"Issuer Name",
	"Validity",
	"Subject Name",
	"SubjectPublicKeyInfo Tag",
	"subjectPublicKeyInfo::AlgorithmIdentifier",
	"subjectPublicKeyInfo::subjectPublicKey",
	"RSAPublicKey Tag",
	"modulusLength",
	"zero padding",
	"modulusLength",
	"modulus",
	"publicExponent length",
	"publicExponent"
};


/**
 * Read X.509 Certificate
 * @param certificate certificate module
 * @param cert X.509 certificate
 */

static bool certificate_read_x509_certificate(CertBlobPtr cert, Buffer &modulus, Buffer &exponent)
{
	Buffer s;
	int length;
	uint8_t padding;
	uint32_t version;
	int modulus_length;
	int exponent_length;
	int error = 0;
	uint8_t exponent_tmp[4] = { 0,0,0,0 };

	modulus.clear();
	exponent.clear();

	s.append(cert->abCert);

	if (!BER::readSequenceTag(&s, length)) /* Certificate (SEQUENCE) */
		goto error1;

	error++;
	if (!BER::readSequenceTag(&s, length)) /* TBSCertificate (SEQUENCE) */
		goto error1;

	error++;
	if (!BER::readContextualTag(&s, 0, length, true))	/* Explicit Contextual Tag [0] */
		goto error1;

	error++;
	if (!BER::readInteger(&s, version)) /* version (INTEGER) */
		goto error1;

	error++;
	version++;

	/* serialNumber */
	uint32_t value;
	if (!BER::readInteger(&s, value)) /* CertificateSerialNumber (INTEGER) */
		goto error1;

	error++;

	/* signature */
	if (!BER::readSequenceTag(&s, length)) /* AlgorithmIdentifier (SEQUENCE) */
		goto error1;
	s.retrieve(length);
	error++;

	/* issuer */
	if (!BER::readSequenceTag(&s, length)) /* Name (SEQUENCE) */
		goto error1;
	s.retrieve(length);
	error++;

	/* validity */
	if (!BER::readSequenceTag(&s, length)) /* Validity (SEQUENCE) */
		goto error1;
	s.retrieve(length);
	error++;

	/* subject */
	if (!BER::readSequenceTag(&s, length)) /* Name (SEQUENCE) */
		goto error1;
	s.retrieve(length);
	error++;

	/* subjectPublicKeyInfo */
	if (!BER::readSequenceTag(&s, length)) /* SubjectPublicKeyInfo (SEQUENCE) */
		goto error1;

	error++;

	/* subjectPublicKeyInfo::AlgorithmIdentifier */
	if (!BER::readSequenceTag(&s, length)) /* AlgorithmIdentifier (SEQUENCE) */
		goto error1;
	s.retrieve(length);
	error++;

	/* subjectPublicKeyInfo::subjectPublicKey */
	if (!BER::readBitString(&s, length, padding)) /* BIT_STRING */
		goto error1;

	error++;

	/* RSAPublicKey (SEQUENCE) */
	if (!BER::readSequenceTag(&s, length)) /* SEQUENCE */
		goto error1;

	error++;

	if (!BER::readIntegerLength(&s, modulus_length)) /* modulus (INTEGER) */
		goto error1;

	error++;

	/* skip zero padding, if any */
	do {
		if (s.length() < 1)
			goto error1;

		padding = s.peekUInt8();
		
		if (padding == 0) {
			s.retrieve(1);
			modulus_length--;
		}
	} while (padding == 0);

	error++;

	if (((int)s.length()) < modulus_length)
		goto error1;

	s.retrieve(modulus, modulus_length);
	error++;

	if (!BER::readIntegerLength(&s, exponent_length)) /* publicExponent (INTEGER) */
		goto error2;

	error++;

	if ((((int)s.length()) < exponent_length) || (exponent_length > 4))
		goto error2;

	s.retrieve(&exponent_tmp[4 - exponent_length], exponent_length);
	exponent.assign(exponent_tmp, 4);

	Rsa::crypto_reverse(modulus.data(), modulus.length());
	Rsa::crypto_reverse(exponent.data(), exponent.length());
	return true;
error2:
	modulus.clear();
	exponent.clear();
error1:
	RDPP_LOG(TAG, ERROR) << "error reading when reading certificate: part=" << certificate_read_errors[error] << " error=" << error;
	return false;
}

bool ProprietaryServerCertificate::computeSignatureHash(uint8_t *signature)
{
	memcpy(signature, initial_signature, sizeof(initial_signature));

    Buffer s;
    s.appendUInt32(CERT_CHAIN_VERSION_1);
    s.appendUInt32(dwSigAlgId);
    s.appendUInt32(dwKeyAlgId);
    s.appendUInt16(wPublicKeyBlobType);
    s.appendUInt16(wPublicKeyBlobLen);
    PublicKeyBlob.write(&s);

	return Digest::digest("md5", (uint8_t *)s.data(), s.length(), signature, Digest::MD5_DIGEST_LENGTH);
}

bool ProprietaryServerCertificate::sign()
{
	uint8_t encryptedSignature[Rsa::TSSK_KEY_LENGTH];
	uint8_t signature[sizeof(initial_signature)];
	
	memcpy(signature, initial_signature, sizeof(initial_signature));

	if (!computeSignatureHash(signature)) {
		RDPP_LOG(TAG, ERROR) << "compute signature hash failed";
		return false;
	}

    Rsa::private_encrypt(signature, sizeof(signature), Rsa::TSSK_KEY_LENGTH,
                         tssk_modulus, tssk_privateExponent, encryptedSignature);

    wSignatureBlobLen = sizeof(encryptedSignature) + sizeof(padding);
	SignatureBlob.assign((char *)encryptedSignature, sizeof(encryptedSignature));
	return true;
}

bool ProprietaryServerCertificate::verify()
{
    uint8_t sig[Rsa::TSSK_KEY_LENGTH];
	uint8_t signature[sizeof(initial_signature)];

	if (wSignatureBlobLen != 72) {
		RDPP_LOG(TAG, ERROR) << "invalid signature length (got " << wSignatureBlobLen << ", expected 72)";
		return false;
	}
	
    Rsa::public_decrypt(SignatureBlob.data(), SignatureBlob.length(),
                        Rsa::TSSK_KEY_LENGTH, tssk_modulus, tssk_exponent, sig);
    
	// Verify signature.
	memcpy(signature, initial_signature, sizeof(initial_signature));
	if (!computeSignatureHash(signature)) {
		RDPP_LOG(TAG, ERROR) << "compute signature hash failed";
		return false;
	}

    return (!memcmp(signature, sig, sizeof(signature)));
}

void X509CertificateChain::getPublicKey(Buffer &n, Buffer &e)
{
	certificate_read_x509_certificate(CertBlobArray[CertBlobArray.size() - 1], n, e);
}
