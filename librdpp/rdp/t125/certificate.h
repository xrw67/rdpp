#ifndef _RDPP_RDP_T125_CERTIFICATE_H_
#define _RDPP_RDP_T125_CERTIFICATE_H_

#include <vector>
#include <core/config.h>
#include <core/buffer.h>
#include <core/crypto.h>
#include <core/log.h>

namespace rdpp
{
#include <core/pshpack1.h>

	#define SIGNATURE_ALG_RSA		0x00000001
	#define KEY_EXCHANGE_ALG_RSA	0x00000001

	#define BB_RSA_KEY_BLOB        		6
	#define BB_RSA_SIGNATURE_BLOB  		8
	
    /// @see: http://msdn.microsoft.com/en-us/library/cc240521.aspx
    enum CertificateType
    {
        CERT_CHAIN_VERSION_1 = 0x00000001,
        CERT_CHAIN_VERSION_2 = 0x00000002,
		CERT_CHAIN_VERSION_MASK = 0x7FFFFFFF,
    };

    /// @see: http://msdn.microsoft.com/en-us/library/cc240520.aspx
    class RSAPublicKey
    {
    public:
        uint32_t magic; // magic is RSA1(0x31415352)
        uint32_t keylen; // modules.length() + sizeof(padding);
        uint32_t bitlen;
        uint32_t datalen;
        uint8_t pubExp[4];
        Buffer modulus; // len = keylen - 8,   MUST be ((bitlen / 8) + 8) bytes.
        char padding[8]; // 8 bytes of zero padding

        RSAPublicKey()
			: magic(0x31415352), keylen(0), bitlen(0), datalen(0)
        {
            memset(padding, 0, sizeof(padding));
        }
        void read(Buffer *data)
        {
            magic = data->readUInt32();
            keylen = data->readUInt32();
            bitlen = data->readUInt32();
            datalen = data->readUInt32();
			data->retrieve(pubExp, 4);
			data->retrieve(modulus, keylen - sizeof(padding));
            data->retrieve(padding, sizeof(padding));
        }
        void write(Buffer *data)
        {
			assert(keylen == (modulus.length() + sizeof(padding)));
			assert(bitlen == ((keylen - 8) * 8));
			assert(datalen == ((bitlen / 8) - 1));

            data->appendUInt32(magic);
            data->appendUInt32(keylen);
            data->appendUInt32(bitlen);
            data->appendUInt32(datalen);
            data->append(pubExp, 4);
            data->append(modulus);
            data->append(padding, sizeof(padding));
        }
        uint16_t size()
        {
            return sizeof(uint32_t) * 5 + keylen;
        }
    };

    /// @summary: microsoft proprietary certificate
    /// @see: http://msdn.microsoft.com/en-us/library/cc240519.aspx
    class ProprietaryServerCertificate 
    {
    public:
        uint32_t dwSigAlgId; // const
        uint32_t dwKeyAlgId; // const
        uint16_t wPublicKeyBlobType; // const
        uint16_t wPublicKeyBlobLen;
        RSAPublicKey PublicKeyBlob;
        uint16_t wSignatureBlobType;
        uint16_t wSignatureBlobLen; // = len(blob) + len(padding)
        Buffer SignatureBlob;
        char padding[8];

        ProprietaryServerCertificate()
            : dwSigAlgId(SIGNATURE_ALG_RSA)
			, dwKeyAlgId(KEY_EXCHANGE_ALG_RSA)
			, wPublicKeyBlobType(BB_RSA_KEY_BLOB)
			, wSignatureBlobType(BB_RSA_SIGNATURE_BLOB)
            , wPublicKeyBlobLen(0)
			, wSignatureBlobLen(0)
        {
            memset(padding, 0, sizeof(padding));
        }
        void getPublicKey(Buffer &n, Buffer &e)
        {
            RDPP_LOG("GCC", DEBUG) << "read RSA public key from proprietary certificate";
			e.assign(PublicKeyBlob.pubExp, 4);
			n.assign(PublicKeyBlob.modulus);
        }
        void read(Buffer *data)
        {
            dwSigAlgId = data->readUInt32();
            dwKeyAlgId = data->readUInt32();
            wPublicKeyBlobType = data->readUInt16();
            wPublicKeyBlobLen = data->readUInt16();
            PublicKeyBlob.read(data);
            wSignatureBlobType = data->readUInt16();
            wSignatureBlobLen = data->readUInt16();
			data->retrieve(SignatureBlob, wSignatureBlobLen - sizeof(padding));
            data->retrieve(padding, sizeof(padding));
        }
        void write(Buffer *data)
        {
			assert(wSignatureBlobLen == (SignatureBlob.length() + sizeof(padding)));

            data->appendUInt32(dwSigAlgId);
            data->appendUInt32(dwKeyAlgId);
            data->appendUInt16(wPublicKeyBlobType);
            data->appendUInt16(wPublicKeyBlobLen);
            PublicKeyBlob.write(data);
            data->appendUInt16(wSignatureBlobType);
            data->appendUInt16(wSignatureBlobLen);
            data->append(SignatureBlob);
            data->append(padding, sizeof(padding));
        }
        /// @summary: compute hash
        bool computeSignatureHash(uint8_t *signature);

        /// @summary: sign proprietary certificate
        /// @see: http://msdn.microsoft.com/en-us/library/cc240778.aspx
        bool sign();
        /// @summary: verify certificate signature
        bool verify();
		uint16_t size()
		{
			return 16 + SignatureBlob.length() + 8 + PublicKeyBlob.size();
		}
    };

	/// @summary: certificate blob, contain x509 data
    /// @see: http://msdn.microsoft.com/en-us/library/cc241911.aspx
    struct CertBlob {
        uint32_t cbCert;
        Buffer abCert;
    };
	typedef shared_ptr<CertBlob> CertBlobPtr;

    /// @summary: X509 certificate chain
    /// @see: http://msdn.microsoft.com/en-us/library/cc241910.aspx
    class X509CertificateChain
    {
    public:
        uint32_t NumCertBlobs;
        std::vector<CertBlobPtr> CertBlobArray;
        // padding; 8 + 4 * NumCertBlobs

        void getPublicKey(Buffer &n, Buffer &e);

        /// @todo: verify x509 signature
        bool verify() { return true; }
        
		void read(Buffer *data)
		{
		    NumCertBlobs = data->readUInt32();
			for (uint32_t i = 0; i < NumCertBlobs; ++i) {
				RDPP_LOG("GCC", DEBUG) << "X.509 Certificate #" << i + 1 << ", length:" << data->peekUInt32();
				CertBlobPtr blob(new CertBlob);

				blob->cbCert = data->readUInt32();
				data->retrieve(blob->abCert, blob->cbCert);
				CertBlobArray.push_back(blob);
			}
			// padding
			data->retrieve(8 + 4 * NumCertBlobs);
		}
        
		void write(Buffer *data)
        {
            assert(CertBlobArray.size() == NumCertBlobs);

            data->appendUInt32(NumCertBlobs);
            for (uint32_t i = 0; i < NumCertBlobs; ++i) {
				CertBlobPtr blob = CertBlobArray[i];

				assert(blob->cbCert == blob->abCert.length());
				data->appendUInt32(blob->cbCert);
				data->append(blob->abCert);
			}
            // padding
            data->append(8 + 4 * NumCertBlobs, '\0');
        }
		uint16_t size()
		{
			uint16_t len = 4;
			for (uint32_t i = 0; i < NumCertBlobs; ++i) {
				len += (4 + CertBlobArray[i]->abCert.length());
			}
			return len;
		}
    };

    /// @summary: Server certificate structure
    /// @see: http://msdn.microsoft.com/en-us/library/cc240521.aspx
    class ServerCertificate
    {
    public:
        uint32_t dwVersion;
        ProprietaryServerCertificate proprietary;
        X509CertificateChain x509;

        ServerCertificate() : dwVersion(0)
        {}
        void read(Buffer *data)
        {
            dwVersion = data->readUInt32();
            switch (dwVersion & CERT_CHAIN_VERSION_MASK) {
            case CERT_CHAIN_VERSION_1: proprietary.read(data); break;
            case CERT_CHAIN_VERSION_2: x509.read(data); break;
            }
        }
        void write(Buffer *data)
        {
            data->appendUInt32(dwVersion);
            switch (dwVersion & CERT_CHAIN_VERSION_MASK) {
            case CERT_CHAIN_VERSION_1: proprietary.write(data); break;
            case CERT_CHAIN_VERSION_2: x509.write(data); break;
            }
        }
        void getPublicKey(Buffer &n, Buffer &e)
        {
            switch (dwVersion & CERT_CHAIN_VERSION_MASK) {
            case CERT_CHAIN_VERSION_1: return proprietary.getPublicKey(n, e);
            case CERT_CHAIN_VERSION_2: return x509.getPublicKey(n, e);
            }
        }
        bool verify()
        {
            switch (dwVersion & CERT_CHAIN_VERSION_MASK) {
            case CERT_CHAIN_VERSION_1: return proprietary.verify();
            case CERT_CHAIN_VERSION_2: return x509.verify();
            }
            return false;
        }
		uint16_t size()
		{
			switch (dwVersion & CERT_CHAIN_VERSION_MASK) {
            case CERT_CHAIN_VERSION_1:
                return sizeof(dwVersion) + proprietary.size();
            case CERT_CHAIN_VERSION_2:
                return sizeof(dwVersion) + x509.size();
            }
            return 0;
		}
    };

#include <core/poppack.h>

} // namespace rdpp

#endif // _RDPP_RDP_T125_CERTIFICATE_H_
