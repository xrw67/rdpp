/**
 * @summary: NTLM Authentication
 * @see: https://msdn.microsoft.com/en-us/library/cc236621.aspx
 */

#ifndef _RDPP_RDP_NLA_NTLM_H_
#define _RDPP_RDP_NLA_NTLM_H_

#include <core/config.h>
#include <core/crypto.h>
#include <rdp/nla/sspi.h>
#include <map>

namespace rdpp {

#include <core/pshpack1.h>

    /// @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    /// @see: https://msdn.microsoft.com/en-us/library/a211d894-21bc-4b8b-86ba-b83d0c167b00#id29
    enum MajorVersion {
        WINDOWS_MAJOR_VERSION_5 = 0x05,
        WINDOWS_MAJOR_VERSION_6 = 0x06,
    };

    /// @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    /// @see: https://msdn.microsoft.com/en-us/library/a211d894-21bc-4b8b-86ba-b83d0c167b00#id30
    enum MinorVersion {
        WINDOWS_MINOR_VERSION_0 = 0x00,
        WINDOWS_MINOR_VERSION_1 = 0x01,
        WINDOWS_MINOR_VERSION_2 = 0x02,
        WINDOWS_MINOR_VERSION_3 = 0x03,
    };

    /// @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    enum NTLMRevision {
        NTLMSSP_REVISION_W2K3 = 0x0F,
    };

    /// @see: https://msdn.microsoft.com/en-us/library/cc236650.aspx

    enum Negotiate {
        NTLMSSP_NEGOTIATE_56 = 0x80000000,
        NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000,
        NTLMSSP_NEGOTIATE_128 = 0x20000000,
        NTLMSSP_NEGOTIATE_VERSION = 0x02000000,
        NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000,
        NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000,
        NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000,
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000,
        NTLMSSP_TARGET_TYPE_SERVER = 0x00020000,
        NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000,
        NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000,
        NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000,
        NTLMSSP_NEGOTIATE_NTLM = 0x00000200,
        NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080,
        NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040,
        NTLMSSP_NEGOTIATE_SEAL = 0x00000020,
        NTLMSSP_NEGOTIATE_SIGN = 0x00000010,
        NTLMSSP_REQUEST_TARGET = 0x00000004,
        NTLM_NEGOTIATE_OEM = 0x00000002,
        NTLMSSP_NEGOTIATE_UNICODE = 0x00000001,
    };

    /// @see: https ://msdn.microsoft.com/en-us/library/cc236646.aspx
    enum AvId {
        MsvAvEOL = 0x0000,
        MsvAvNbComputerName = 0x0001,
        MsvAvNbDomainName = 0x0002,
        MsvAvDnsComputerName = 0x0003,
        MsvAvDnsDomainName = 0x0004,
        MsvAvDnsTreeName = 0x0005,
        MsvAvFlags = 0x0006,
        MsvAvTimestamp = 0x0007,
        MsvAvSingleHost = 0x0008,
        MsvAvTargetName = 0x0009,
        MsvChannelBindings = 0x000A,
    };

    /// @summary: Signature for message
    /// @see: https ://msdn.microsoft.com/en-us/library/cc422952.aspx
    struct MessageSignatureEx {
        uint32_t Version;
        uint8_t Checksum[8];
        uint32_t SeqNum;

        MessageSignatureEx() : Version(0x00000001), SeqNum(0)
        {
            memset(Checksum, 0, sizeof(Checksum));
        }
    };

    /// @summary: Version structure as describe in NTLM spec
    /// @see: https://msdn.microsoft.com/en-us/library/cc236654.aspx
    struct NTLMVersion {
        uint8_t ProductMajorVersion;
        uint8_t ProductMinorVersion;
        uint16_t ProductBuild;
        uint16_t Reserved1;
        uint8_t reserved2;
        uint8_t NTLMRevisionCurrent;

        NTLMVersion()
            : ProductMajorVersion(WINDOWS_MAJOR_VERSION_6)
            , ProductMinorVersion(WINDOWS_MINOR_VERSION_0)
            , ProductBuild(6002), Reserved1(0), reserved2(0)
            , NTLMRevisionCurrent(NTLMSSP_REVISION_W2K3)
        {}
    };

    /// @summary: Message send from client to server to negotiate capability of NTLM Authentication
    /// @see: https://msdn.microsoft.com/en-us/library/cc236641.aspx
    struct NegotiateMessage {
        struct {
            uint8_t Signature[8];
            uint32_t MessageType;

            uint32_t NegotiateFlags;

            uint16_t DomainNameLen;
            uint16_t DomainNameMaxLen;
            uint32_t DomainNameBufferOffset;

            uint16_t WorkstationLen;
            uint16_t WorkstationMaxLen;
            uint32_t WorkstationBufferOffset;
        } h;
		NTLMVersion version;
        Buffer payload;

        NegotiateMessage()
        {
            memset(&h, 0, sizeof(h));
            memcpy(h.Signature, "NTLMSSP\x00", 8);
            h.MessageType = 0x00000001;
        }
        void read(Buffer *s)
        {
            s->retrieve(&h, sizeof(h));
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				s->retrieve(&version, sizeof(version));
            s->retrieve(payload, h.DomainNameLen + h.WorkstationLen);
        }
        void write(Buffer *s)
        {
            assert(payload.length() == (h.DomainNameLen + h.WorkstationLen));
            s->append(&h, sizeof(h));
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				s->append(&version, sizeof(version));
            s->append(payload);
        }
    };

    /// @see: https://msdn.microsoft.com/en-us/library/cc236646.aspx
    struct AvPair {
        uint16_t AvId;
        uint16_t AvLen;
        Buffer Value;

        AvPair(uint16_t id = 0, uint16_t len = 0) : AvId(id), AvLen(len) {}
        void read(Buffer *s)
        {
            AvId = s->readUInt16();
            AvLen = s->readUInt16();
            s->retrieve(Value, AvLen);
        }
        void write(Buffer *s)
        {
            assert(Value.length() == AvLen);

            s->appendUInt16(AvId);
            s->appendUInt16(AvLen);
            s->append(Value);
        }
    };
    typedef std::map<uint16_t, Buffer> AvPairMap;

    /// @summary: Message send from server to client contains server challenge
    /// @see: https://msdn.microsoft.com/en-us/library/cc236642.aspx
    struct ChallengeMessage {
        struct {
            char Signature[8]; // "NTLMSSP\x00"
            uint32_t MessageType; // 0x00000002

            uint16_t TargetNameLen;
            uint16_t TargetNameMaxLen;
            uint32_t TargetNameBufferOffset;

            uint32_t NegotiateFlags;

            uint8_t ServerChallenge[8];
            char Reserved[8];  // "\0" * 8

            uint16_t TargetInfoLen;
            uint16_t TargetInfoMaxLen;
            uint32_t TargetInfoBufferOffset;
        } h;
		NTLMVersion version;
        Buffer payload;

        ChallengeMessage()
        {
            memset(&h, 0, sizeof(h));
            memcpy(h.Signature, "NTLMSSP\x00", 8);
            h.MessageType = 0x00000002;
        }
        void read(Buffer *s)
        {
            s->retrieve(&h, sizeof(h));
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				s->retrieve(&version, sizeof(version));
            s->retrieve(payload, h.TargetNameLen + h.TargetInfoLen);
        }
        void write(Buffer *s)
        {
            assert(payload.length() == (h.TargetNameLen + h.TargetInfoLen));
            s->append(&h, sizeof(h));
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				s->append(&version, sizeof(version));
            s->append(payload);
        }
		uint32_t payloadOffset(uint32_t offset)
		{
			offset -= sizeof(h);
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				offset -= sizeof(version);
			return offset;
		}
        string getTargetName()
        {
            return std::string((char *)payload.data() + payloadOffset(h.TargetNameBufferOffset), h.TargetNameLen);
        }
        void getTargetInfo(Buffer *info)
        {
            info->assign(payload.data() + payloadOffset(h.TargetInfoBufferOffset), h.TargetInfoLen);
        }

        /// @summary: Parse Target info field to retrieve array of AvPair
        /// @return: {map(AvId, str)}
        void getTargetInfoAsAvPairArray(AvPairMap &result)
        {
            Buffer s;
			getTargetInfo(&s);

            while (s.length() > 0) {
                AvPair avPair;
                avPair.read(&s);
                if (avPair.AvId == MsvAvEOL)
                    return;

                result[avPair.AvId] = avPair.Value;
            }
        }
    };

    /// @summary: Last message in ntlm authentication
    /// @see: https://msdn.microsoft.com/en-us/library/cc236643.aspx
    struct AuthenticateMessage {
        struct {
            char Signature[8]; // "NTLMSSP\x00"
            uint32_t MessageType; // 0x00000003

            uint16_t LmChallengeResponseLen;
            uint16_t LmChallengeResponseMaxLen;
            uint32_t LmChallengeResponseBufferOffset;

            uint16_t NtChallengeResponseLen;
            uint16_t NtChallengeResponseMaxLen;
            uint32_t NtChallengeResponseBufferOffset;

            uint16_t DomainNameLen;
            uint16_t DomainNameMaxLen;
            uint32_t DomainNameBufferOffset;

            uint16_t UserNameLen;
            uint16_t UserNameMaxLen;
            uint32_t UserNameBufferOffset;

            uint16_t WorkstationLen;
            uint16_t WorkstationMaxLen;
            uint32_t WorkstationBufferOffset;

            uint16_t EncryptedRandomSessionLen;
            uint16_t EncryptedRandomSessionMaxLen;
            uint32_t EncryptedRandomSessionBufferOffset;

            uint32_t NegotiateFlags;
        } h;
		NTLMVersion version;
		uint8_t MIC[16];
        Buffer payload;

        AuthenticateMessage()
        {
            memset(&h, 0, sizeof(h));
            memcpy(h.Signature, "NTLMSSP\x00", 8);
            h.MessageType = 0x00000003;
        }
        void read(Buffer *s)
        {
            s->retrieve(&h, sizeof(h));
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				s->retrieve(&version, sizeof(version));
			s->retrieve(MIC, sizeof(MIC));
            s->retrieve(payload, h.LmChallengeResponseLen + h.NtChallengeResponseLen +
								 h.DomainNameLen + h.UserNameLen +
								 h.WorkstationLen + h.EncryptedRandomSessionLen);
        }
        void write(Buffer *s)
        {
            assert(payload.length() == (h.LmChallengeResponseLen + h.NtChallengeResponseLen +
                h.DomainNameLen + h.UserNameLen + h.WorkstationLen + h.EncryptedRandomSessionLen));

            s->append(&h, sizeof(h));
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				s->append(&version, sizeof(version));
			s->append(MIC, sizeof(MIC));
            s->append(payload);
        }
        void setup(uint32_t negFlag, const string &domain, const string &user,
                   const Buffer &ntChallengeResponse, const Buffer &lmChallengeResponse,
                   const uint8_t *encryptedRandomSessionKey, const string &workstation)
        {
            h.NegotiateFlags = negFlag;
            uint32_t offset = sizeof(h);
			if (h.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
				offset += sizeof(version);
			offset += sizeof(MIC);

            h.DomainNameLen = h.DomainNameMaxLen = domain.length();
            h.DomainNameBufferOffset = offset;
            payload.append(domain);
            offset += domain.length();

            h.UserNameLen = h.UserNameMaxLen = user.length();
            h.UserNameBufferOffset = offset;
            payload.append(user);
            offset += user.length();

            h.WorkstationLen = h.WorkstationMaxLen = workstation.length();
            h.WorkstationBufferOffset = offset;
            payload.append(workstation);
            offset += workstation.length();

            h.LmChallengeResponseLen = h.LmChallengeResponseMaxLen = lmChallengeResponse.length();
            h.LmChallengeResponseBufferOffset = offset;
            payload.append(lmChallengeResponse);
            offset += lmChallengeResponse.length();

            h.NtChallengeResponseLen = h.NtChallengeResponseMaxLen = ntChallengeResponse.length();
            h.NtChallengeResponseBufferOffset = offset;
            payload.append(ntChallengeResponse);
            offset += ntChallengeResponse.length();

            h.EncryptedRandomSessionLen = h.EncryptedRandomSessionMaxLen = 16;
            h.EncryptedRandomSessionBufferOffset = offset;
            payload.append(encryptedRandomSessionKey, 16);
        }
    };

#include <core/poppack.h>

    /// @summary: Handle NTLMv2 Authentication
    class NTLMv2 : public IAuthenticationProtocol
    {
    public:
        NTLMv2();

		bool init(const string &domain, const string &user, const string &passwd);

        /// @summary: generate first handshake messgae 
        virtual bool getNegotiateMessage(Buffer *s);

        /// @summary: Client last handshake message
        /// @see: https ://msdn.microsoft.com/en-us/library/cc236676.aspx
        virtual bool getAuthenticateMessage(Buffer *challengeRequest, Buffer *message);

        /// @summary: return encoded credentials accorded with authentication protocol nego
        /// @return: (domain, username, password)
        virtual void getEncodedCredentials(string &domain, string &user, string &password);

		 /// @summary: Encrypt function for NTLMv2 security service
        /// @param data: data to encrypt
        /// @return: {str} encrypted data
        virtual bool GSS_WrapEx(Buffer *data);

        /// @summary: decrypt data with key exchange in Authentication protocol
        /// @param data: {str}
        virtual bool GSS_UnWrapEx(Buffer *data);
    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(NTLMv2);

		bool _enableUnicode;

        string _domain;
        string _user;
        string _password;
		
		// https://msdn.microsoft.com/en-us/library/cc236700.aspx
        uint8_t _responseKeyNT[Digest::MD5_DIGEST_LENGTH];
        uint8_t _responseKeyLM[Digest::MD5_DIGEST_LENGTH];

		// For MIC computation
        Buffer _negotiateMessage;
        Buffer _challengeMessage;
        Buffer _authenticateMessage;

		Rc4 _encryptHandle;
        Rc4 _decryptHandle;
        uint8_t _signingKey[16];
        uint8_t _verifyKey[16];
        uint32_t _seqNum;
    };

} // namespace rdpp

#endif // _RDPP_RDP_NLA_NTLM_H_
