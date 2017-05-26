/**
 * @summary: RDP extended license
 * @see: http://msdn.microsoft.com/en-us/library/cc241880.aspx
 */
#ifndef _RDPP_RDP_LIC_H_
#define _RDPP_RDP_LIC_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/string_util.h>
#include <core/unicode/utf.h>
#include <rdp/sec.h>
#include <vector>

namespace rdpp {

#include <core/pshpack1.h>

	class SecLayer;

	#define CLIENT_OS_ID_WINNT_351			0x01000000
	#define CLIENT_OS_ID_WINNT_40			0x02000000
	#define CLIENT_OS_ID_WINNT_50			0x03000000
	#define CLIENT_OS_ID_WINNT_POST_52		0x04000000

	#define CLIENT_IMAGE_ID_MICROSOFT		0x00010000
	#define CLIENT_IMAGE_ID_CITRIX			0x00020000

	/* License Key Exchange Algorithms */
	#define KEY_EXCHANGE_ALG_RSA			0x00000001

    /// @summary: License packet message type
    enum MessageType {
        MSG_TYPE_LICENSE_REQUEST = 0x01,
        MSG_TYPE_PLATFORM_CHALLENGE = 0x02,
        MSG_TYPE_NEW_LICENSE = 0x03,
        MSG_TYPE_UPGRADE_LICENSE = 0x04,
        MSG_TYPE_LICENSE_INFO = 0x12,
        MSG_TYPE_NEW_LICENSE_REQUEST = 0x13,
        MSG_TYPE_PLATFORM_CHALLENGE_RESPONSE = 0x15,
        MSG_TYPE_ERROR_ALERT = 0xFF,
    };

    /// @summary: License error message code
    /// @see: http://msdn.microsoft.com/en-us/library/cc240482.aspx
    enum ErrorCode {
        ERR_INVALID_SERVER_CERTIFICATE = 0x00000001,
        ERR_NO_LICENSE = 0x00000002,
        ERR_INVALID_SCOPE = 0x00000004,
        ERR_NO_LICENSE_SERVER = 0x00000006,
        STATUS_VALID_CLIENT = 0x00000007,
        ERR_INVALID_CLIENT = 0x00000008,
        ERR_INVALID_PRODUCTID = 0x0000000B,
        ERR_INVALID_MESSAGE_LEN = 0x0000000C,
        ERR_INVALID_MAC = 0x00000003,
    };

    /// @summary: Automata state transition
    /// @see: http://msdn.microsoft.com/en-us/library/cc240482.aspx
    enum StateTransition {
        ST_TOTAL_ABORT = 0x00000001,
        ST_NO_TRANSITION = 0x00000002,
        ST_RESET_PHASE_TO_START = 0x00000003,
        ST_RESEND_LAST_MESSAGE = 0x00000004,
    };

    /// @summary: Binary blob data type
    /// @see: http://msdn.microsoft.com/en-us/library/cc240481.aspx
    enum BinaryBlobType {
        BB_ANY_BLOB = 0x0000,
        BB_DATA_BLOB = 0x0001,
        BB_RANDOM_BLOB = 0x0002,
        BB_CERTIFICATE_BLOB = 0x0003,
        BB_ERROR_BLOB = 0x0004,
        BB_ENCRYPTED_DATA_BLOB = 0x0009,
        BB_KEY_EXCHG_ALG_BLOB = 0x000D,
        BB_SCOPE_BLOB = 0x000E,
        BB_CLIENT_USER_NAME_BLOB = 0x000F,
        BB_CLIENT_MACHINE_NAME_BLOB = 0x0010,
    };

    /// @summary: Preambule version
    enum Preambule {
        PREAMBLE_VERSION_2_0 = 0x2,
        PREAMBLE_VERSION_3_0 = 0x3,
        EXTENDED_ERROR_MSG_SUPPORTED = 0x80,
    };

    /// @summary: Blob use by license manager to exchange security data
    /// @see: http://msdn.microsoft.com/en-us/library/cc240481.aspx
    struct LicenseBinaryBlob {
        uint16_t wBlobType;
        uint16_t wBlobLen;
        Buffer blobData; // length = wBlobLen;

        LicenseBinaryBlob(uint16_t blobType = BB_ANY_BLOB)
            : wBlobType(blobType), wBlobLen(0)
        {}
        void read(Buffer *s)
        {
            wBlobType = s->readUInt16();
            wBlobLen = s->readUInt16();
            s->retrieve(blobData, wBlobLen);
        }
        
        void write(Buffer *s)
        {
            assert(blobData.length() == wBlobLen);

            s->appendUInt16(wBlobType);
            s->appendUInt16(wBlobLen);
            s->append(blobData);
        }
        uint16_t size()
        {
            return 4 + blobData.length();
        }
        void append(const void *data, size_t len)
        {
            wBlobLen += len;
			blobData.append(data, len);
        }
    };

    /// @summary: License error message
    /// @see: http://msdn.microsoft.com/en-us/library/cc240482.aspx
    struct LicensingErrorMessage {
        uint32_t dwErrorCode;
        uint32_t dwStateTransition;
        LicenseBinaryBlob blob;

        LicensingErrorMessage() : blob(BB_ANY_BLOB)
        {}
        void read(Buffer *s)
        {
            dwErrorCode = s->readUInt32();
            dwStateTransition = s->readUInt32();
            blob.read(s);
        }
        void write(Buffer *s)
        {
            s->appendUInt32(dwErrorCode);
            s->appendUInt32(dwStateTransition);
            blob.write(s);
        }
        uint16_t size()
        {
            return 8 + blob.size();
        }
    };

    /// @summary: License server product information
    /// @see: http://msdn.microsoft.com/en-us/library/cc241915.aspx
    struct ProductInformation {
        uint32_t dwVersion;
        uint32_t cbCompanyName;
        // (unicode) may contain "Microsoft Corporation" from server microsoft
        string pbCompanyName;
        uint32_t cbProductId;
        // (unicode) may contain "A02" from microsoft license server
        string pbProductId;

        ProductInformation()
            : pbCompanyName(utf::ascii_to_unicode("Microsoft Corporation"))
            , pbProductId(utf::ascii_to_unicode("A02"))
        {
            cbCompanyName = pbCompanyName.length();
            cbProductId = pbProductId.length();
        }
        void read(Buffer *s)
        {
            dwVersion = s->readUInt32();
            cbCompanyName = s->readUInt32();
            pbCompanyName = s->retrieveAsString(cbCompanyName);
            cbProductId = s->readUInt32();
            pbProductId = s->retrieveAsString(cbProductId);
        }
        void write(Buffer *s)
        {
            assert(pbCompanyName.length() == cbCompanyName);
            assert(pbProductId.length() == cbProductId);

            s->appendUInt32(dwVersion);
            s->appendUInt32(cbCompanyName);
            s->append(pbCompanyName);
            s->appendUInt32(cbProductId);
        }
    };

    /// @summary: Use in license nego
    /// @see: http://msdn.microsoft.com/en-us/library/cc241917.aspx
    struct Scope {
        LicenseBinaryBlob scope;

        Scope() : scope(BB_SCOPE_BLOB)
        {}
        void read(Buffer *s)
        { scope.read(s); }
        void write(Buffer *s)
        { scope.write(s); }
    };
	typedef shared_ptr<Scope> ScopePtr;

    /// @summary: Use in license nego
    /// @see: http://msdn.microsoft.com/en-us/library/cc241916.aspx
    struct ScopeList {
        uint32_t scopeCount;
        std::vector<ScopePtr> scopeArray;

        ScopeList() : scopeCount(0)
        {}
        void read(Buffer *s)
        {
            scopeCount = s->readUInt32();
            for (size_t i = 0; i < scopeCount; ++i) {
                ScopePtr scope(new Scope);
                scope->read(s);
                scopeArray.push_back(scope);
            }
        }
        void write(Buffer *s)
        {
            assert(scopeArray.size() == scopeCount);
            s->appendUInt32(scopeCount);
            for (size_t i = 0; i < scopeCount; ++i)
                scopeArray[i]->write(s);
        }
    };

    /// @summary:  Send by server to signal license request
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc241914.aspx
    struct ServerLicenseRequest {
        Buffer serverRandom;  // len = 32 bytes
        ProductInformation productInfo;
        LicenseBinaryBlob keyExchangeList;
        LicenseBinaryBlob serverCertificate;
        ScopeList scopeList;

        ServerLicenseRequest()
            : keyExchangeList(BB_KEY_EXCHG_ALG_BLOB)
            , serverCertificate(BB_CERTIFICATE_BLOB)
        {}

        void read(Buffer *s)
        {
            s->retrieve(serverRandom, 32);
            productInfo.read(s);
            keyExchangeList.read(s);
            serverCertificate.read(s);
            scopeList.read(s);
        }

        void write(Buffer *s)
        {
            assert(serverRandom.length() == 32);
            s->append(serverRandom);
            productInfo.write(s);
            keyExchangeList.write(s);
            serverCertificate.write(s);
            scopeList.write(s);
        }
    };

    /// @summary:  Send by client to ask new license for client.
    /// @see: http://msdn.microsoft.com/en-us/library/cc241918.aspx
    struct ClientNewLicenseRequest {
        uint32_t preferredKeyExchangeAlg;
        uint32_t platformId;
        Buffer clientRandom; // const 32 bytes
        LicenseBinaryBlob encryptedPreMasterSecret;
        LicenseBinaryBlob ClientUserName;
        LicenseBinaryBlob ClientMachineName;

        ClientNewLicenseRequest()
            // RSA and must be only RSA
            : preferredKeyExchangeAlg(KEY_EXCHANGE_ALG_RSA)
            // pure microsoft client; -)
            // http://msdn.microsoft.com/en-us/library/1040af38-c733-4fb3-acd1-8db8cc979eda#id10
            , platformId(CLIENT_OS_ID_WINNT_POST_52 | CLIENT_IMAGE_ID_MICROSOFT)
            , encryptedPreMasterSecret(BB_RANDOM_BLOB)
            , ClientUserName(BB_CLIENT_USER_NAME_BLOB)
            , ClientMachineName(BB_CLIENT_MACHINE_NAME_BLOB)
        {
        }
        void read(Buffer *s)
        {
            preferredKeyExchangeAlg = s->readUInt32();
            platformId = s->readUInt32();
            s->retrieve(clientRandom, 32);
            encryptedPreMasterSecret.read(s);
            ClientUserName.read(s);
            ClientMachineName.read(s);
        }
        void write(Buffer *s)
        {
            assert(clientRandom.length() == 32);
            s->appendUInt32(preferredKeyExchangeAlg);
            s->prependUInt32(platformId);
            s->append(clientRandom);
            encryptedPreMasterSecret.write(s);
        }
        uint16_t size()
        {
            return 8 + clientRandom.length() + 
                   encryptedPreMasterSecret.size() +
                   ClientUserName.size() + ClientMachineName.size();
        }
    };

    /// @summary: challenge send from server to client
    /// @see: http://msdn.microsoft.com/en-us/library/cc241921.aspx
    struct ServerPlatformChallenge {
        uint32_t connectFlags;
        LicenseBinaryBlob encryptedPlatformChallenge;
        uint8_t MACData[16];

        ServerPlatformChallenge() : encryptedPlatformChallenge(BB_ANY_BLOB) , connectFlags(0)
        {}
        void read(Buffer *s)
        {
            connectFlags = s->readUInt32();
            encryptedPlatformChallenge.read(s);
            s->retrieve(MACData, 16);
        }
        void write(Buffer *s)
        {
            s->appendUInt32(connectFlags);
            encryptedPlatformChallenge.write(s);
            s->append(MACData, 16);
        }
    };

    /// @summary: client challenge response
    /// @see: http://msdn.microsoft.com/en-us/library/cc241922.aspx
    struct ClientPLatformChallengeResponse {
        LicenseBinaryBlob encryptedPlatformChallengeResponse;
        LicenseBinaryBlob encryptedHWID;
        uint8_t MACData[16];

        ClientPLatformChallengeResponse()
            : encryptedPlatformChallengeResponse(BB_DATA_BLOB), encryptedHWID(BB_DATA_BLOB)
        { }
        void read(Buffer *s)
        {
            encryptedPlatformChallengeResponse.read(s);
            encryptedHWID.read(s);
            s->retrieve(MACData, 16);
        }
        void write(Buffer *s)
        {
            encryptedPlatformChallengeResponse.write(s);
            encryptedHWID.write(s);
            s->append(MACData, 16);
        }
        uint16_t size()
        {
            return encryptedPlatformChallengeResponse.size() +
                   encryptedHWID.size() + 16;
        }
    };
    
    /// @summary: Create a licensing error message that accept client
    /// server automata message
    void createValidClientLicensingErrorMessage(Buffer *s);

    /// @summary: handle license automata(client side)
    /// @see: http://msdn.microsoft.com/en-us/library/cc241890.aspx
    class LicenseManager
    {
    public:
        /// @param transport : layer use to send packet
        LicenseManager(SecLayer *transport);

        /// @summary: receive license packet from PDU layer
        /// @return true when license automata is finish
        bool recv(Buffer *s);

		void sendLicensePacket(uint8_t type, Buffer *data);

        /// @summary: Create new license request in response to server license request
        /// @param licenseRequest: {ServerLicenseRequest}
        /// @see: http ://msdn.microsoft.com/en-us/library/cc241989.aspx
        /// @see: http ://msdn.microsoft.com/en-us/library/cc241918.aspx
        void sendClientNewLicenseRequest(ServerLicenseRequest &licenseRequest);

        /// @summary: generate valid challenge response
        /// @param platformChallenge: {ServerPlatformChallenge}
        void sendClientChallengeResponse(ServerPlatformChallenge &platformChallenge);

		void setUsername(const string &username)
		{ _username = username; }

		void setHostname(const string &hostname)
		{ _hostname = hostname; }
	private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(LicenseManager);

        SecLayer *_transport;
        string _username;
        string _hostname;
        uint8_t _macSaltKey[MAC_SALT_KEY_LENGTH];
        uint8_t _licensingEncryptionKey[LICENSING_ENCRYPTION_KEY_LENGTH];
    };

#include <core/poppack.h>

} // namespace rdpp

#endif // _RDPP_RDP_LIC_H_
