/*
 * RDP Standard security layer
 */
#ifndef _RDPP_RDP_SEC_H_
#define _RDPP_RDP_SEC_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/layer.h>
#include <core/crypto.h>
#include <core/string_util.h>
#include <core/unicode/utf.h>

namespace rdpp {

    class ServerCertificate;
    class ClientSettings;
    class ServerSettings;
    class MCSProxySender;
    class LicenseManager;

	bool security_master_secret(const uint8_t* premaster_secret, const uint8_t* client_random,
		const uint8_t* server_random, uint8_t* output);

	bool security_session_key_blob(const uint8_t* master_secret, const uint8_t* client_random,
		const uint8_t* server_random, uint8_t* output);
	
	void security_mac_salt_key(const uint8_t* session_key_blob, const uint8_t* client_random,
		const uint8_t* server_random, uint8_t* output);
	
	bool security_licensing_encryption_key(const uint8_t* session_key_blob, const uint8_t* client_random,
		const uint8_t* server_random, uint8_t* output);

	bool security_mac_data(const uint8_t* mac_salt_key, const uint8_t* data, uint8_t length,
		uint8_t* output);

#include <core/pshpack1.h>

	// Cryptographic Lengths
	#define CLIENT_RANDOM_LENGTH			32
	#define SERVER_RANDOM_LENGTH			32
	#define MASTER_SECRET_LENGTH			48
	#define PREMASTER_SECRET_LENGTH			48
	#define SESSION_KEY_BLOB_LENGTH			48
	#define MAC_SALT_KEY_LENGTH				16
	#define LICENSING_ENCRYPTION_KEY_LENGTH	16
	#define HWID_PLATFORM_ID_LENGTH			4
	#define HWID_UNIQUE_DATA_LENGTH			16
	#define HWID_LENGTH						20
	#define LICENSING_PADDING_SIZE			8

    /// @summary: Microsoft security flags
    /// @see: http://msdn.microsoft.com/en-us/library/cc240579.aspx
    enum SecurityFlag {
        SEC_EXCHANGE_PKT = 0x0001,
        SEC_TRANSPORT_REQ = 0x0002,
        RDP_SEC_TRANSPORT_RSP = 0x0004,
        SEC_ENCRYPT = 0x0008,
        SEC_RESET_SEQNO = 0x0010,
        SEC_IGNORE_SEQNO = 0x0020,
        SEC_INFO_PKT = 0x0040,
        SEC_LICENSE_PKT = 0x0080,
        SEC_LICENSE_ENCRYPT_CS = 0x0200,
        SEC_LICENSE_ENCRYPT_SC = 0x0200,
        SEC_REDIRECTION_PKT = 0x0400,
        SEC_SECURE_CHECKSUM = 0x0800,
        SEC_AUTODETECT_REQ = 0x1000,
        SEC_AUTODETECT_RSP = 0x2000,
        SEC_HEARTBEAT = 0x4000,
        SEC_FLAGSHI_VALID = 0x8000,
    };

    /// Client capabilities informations
    enum InfoFlag {
        INFO_MOUSE = 0x00000001,
        INFO_DISABLECTRLALTDEL = 0x00000002,
        INFO_AUTOLOGON = 0x00000008,
        INFO_UNICODE = 0x00000010,
        INFO_MAXIMIZESHELL = 0x00000020,
        INFO_LOGONNOTIFY = 0x00000040,
        INFO_COMPRESSION = 0x00000080,
        INFO_ENABLEWINDOWSKEY = 0x00000100,
        INFO_REMOTECONSOLEAUDIO = 0x00002000,
        INFO_FORCE_ENCRYPTED_CS_PDU = 0x00004000,
        INFO_RAIL = 0x00008000,
        INFO_LOGONERRORS = 0x00010000,
        INFO_MOUSE_HAS_WHEEL = 0x00020000,
        INFO_PASSWORD_IS_SC_PIN = 0x00040000,
        INFO_NOAUDIOPLAYBACK = 0x00080000,
        INFO_USING_SAVED_CREDS = 0x00100000,
        INFO_AUDIOCAPTURE = 0x00200000,
        INFO_VIDEO_DISABLE = 0x00400000,
        INFO_CompressionTypeMask = 0x00001E00,
    };

    /// Network performances flag
    enum PerfFlag {
        PERF_DISABLE_WALLPAPER = 0x00000001,
        PERF_DISABLE_FULLWINDOWDRAG = 0x00000002,
        PERF_DISABLE_MENUANIMATIONS = 0x00000004,
        PERF_DISABLE_THEMING = 0x00000008,
        PERF_DISABLE_CURSOR_SHADOW = 0x00000020,
        PERF_DISABLE_CURSORSETTINGS = 0x00000040,
        PERF_ENABLE_FONT_SMOOTHING = 0x00000080,
        PERF_ENABLE_DESKTOP_COMPOSITION = 0x00000100,
    };

    /// IPv4 or IPv6 address style
    enum AfInet {
        _AF_INET = 0x00002,
        _AF_INET6 = 0x0017,
    };

    /// @summary: Add more client informations
    struct RDPExtendedInfo {
        uint16_t clientAddressFamily;
        uint16_t cbClientAddress;
        string clientAddress; // readLen = self.cbClientAddress, unicode
        uint16_t cbClientDir;
        string clientDir; //readLen = cbClientDir, unicode
        char clientTimeZone[172]; // TODO make tiomezone
        uint32_t clientSessionId;
        uint32_t performanceFlags;

        RDPExtendedInfo() : clientAddressFamily(_AF_INET)
			, cbClientAddress(0), cbClientDir(0)
            , clientSessionId(0), performanceFlags(0) 
        {
            memset(clientTimeZone, 0, sizeof(clientTimeZone));
        }
        void read(Buffer *s)
        {
            clientAddressFamily = s->readUInt16();
            cbClientAddress = s->readUInt16();
            clientAddress = s->retrieveAsString(cbClientAddress);
            cbClientDir = s->readUInt16();
            clientDir = s->retrieveAsString(cbClientDir);
            s->retrieve(clientTimeZone, sizeof(clientTimeZone));
            clientSessionId = s->readUInt32();
            performanceFlags = s->readUInt32();
        }
        void write(Buffer *s)
        {
			assert(cbClientAddress == clientAddress.length());
			assert(cbClientDir == clientDir.length());

            s->appendUInt16(clientAddressFamily);
            s->appendUInt16(cbClientAddress);
            s->append(clientAddress);
            s->appendUInt16(cbClientDir);
            s->append(clientDir);
            s->append(clientTimeZone, sizeof(clientTimeZone));
            s->appendUInt32(clientSessionId);
            s->appendUInt32(performanceFlags);
        }
		void setClientAddress(const string &s)
		{
			clientAddress = utf::ascii_to_unicode(s);
			cbClientAddress = clientAddress.length();
		}
		string getCientAddress()
		{
			return utf::unicode_to_ascii(clientDir);
		}
		void setClientDir(const string &s)
		{
			clientDir = utf::ascii_to_unicode(s);
			cbClientDir = clientDir.length();
		}
		string getClientDir()
		{
			return utf::unicode_to_ascii(clientDir);
		}
    };

    /// @summary: Client informations
    /// Contains credentials(very important packet)
    /// @see: http://msdn.microsoft.com/en-us/library/cc240475.aspx
    struct RDPInfo {
        struct {
            uint32_t codePage; // code page
            uint32_t flag; // support flag
            uint16_t cbDomain;
            uint16_t cbUserName;
            uint16_t cbPassword;
            uint16_t cbAlternateShell;
            uint16_t cbWorkingDir;
        } d;
        string domain; // unicode, microsoft domain
        string userName; // unicode, 
        string password; // unicode, 
        string alternateShell; // unicode, shell execute at start of session
        string workingDir; // unicode, working directory for session
        shared_ptr<RDPExtendedInfo> extendedInfo;

        RDPInfo()
        {
            memset(&d, 0, sizeof(d));
            d.flag = INFO_MOUSE | INFO_UNICODE | INFO_LOGONNOTIFY | INFO_LOGONERRORS |
                     INFO_DISABLECTRLALTDEL | INFO_ENABLEWINDOWSKEY | INFO_MAXIMIZESHELL;
        }
        void read(Buffer *s)
        {
			s->retrieve(&d, sizeof(d));
            domain = s->retrieveAsString(d.cbDomain);
			s->readUInt16(); // null terminator
            userName = s->retrieveAsString(d.cbUserName);
			s->readUInt16(); // null terminator
            password = s->retrieveAsString(d.cbPassword);
			s->readUInt16(); // null terminator
            alternateShell = s->retrieveAsString(d.cbAlternateShell);
			s->readUInt16(); // null terminator
            workingDir = s->retrieveAsString(d.cbWorkingDir);
			s->readUInt16(); // null terminator

            if (extendedInfo)
                extendedInfo->read(s);
        }
        void write(Buffer *s)
        {
			assert(d.cbDomain == domain.length());
			assert(d.cbUserName == userName.length());
			assert(d.cbPassword == password.length());
			assert(d.cbAlternateShell == alternateShell.length());
			assert(d.cbWorkingDir == workingDir.length());

            s->append(&d, sizeof(d));
            s->append(domain);
			s->appendUInt16(0); // null terminator
            s->append(userName);
			s->appendUInt16(0); // null terminator
            s->append(password);
			s->appendUInt16(0); // null terminator
            s->append(alternateShell);
			s->appendUInt16(0); // null terminator
            s->append(workingDir);
			s->appendUInt16(0); // null terminator

            if (extendedInfo)
                extendedInfo->write(s);
        }
		void setDomain(const string &s)
		{
			domain = utf::ascii_to_unicode(s);
			d.cbDomain = domain.length();
		}
		string getDomain()
		{
			return utf::unicode_to_ascii(domain);
		}
		void setUsername(const string &s)
		{
			userName = utf::ascii_to_unicode(s);
			d.cbUserName = userName.length();
		}
		string getUsername()
		{
			return utf::unicode_to_ascii(userName);
		}
		void setPassword(const string &s)
		{
			password = utf::ascii_to_unicode(s);
			d.cbPassword = password.length();
		}
		string getPassword()
		{
			return utf::unicode_to_ascii(password);
		}
		void setAlternateShell(const string &s)
		{
			alternateShell = utf::ascii_to_unicode(s);
			d.cbAlternateShell = alternateShell.length();
		}
		string getAlternateShell()
		{
			return utf::unicode_to_ascii(alternateShell);
		}
		void setWorkingDir(const string &s)
		{
			workingDir = utf::ascii_to_unicode(s);
			d.cbWorkingDir = workingDir.length();
		}
		string getWorkingDir()
		{
			return utf::unicode_to_ascii(workingDir);
		}
    };

#include <core/poppack.h>

    /// @summary: Standard RDP security layer
    /// This layer is Transparent as possible for upper layer
    class SecLayer : public Layer, public FastPathLayer
    {
    public:
        /// @param presentation: Layer (generally pdu layer)
        SecLayer(Layer *presentation, FastPathLayer *fastPathListener, bool serverMode);

        void init();

        /// @summary: if basic RDP security layer is activate decrypt
        ///            else pass to upper layer
        /// @param data : {Buffer} input Buffer
        void dataReceived(Buffer *data);

        /// @summary: if basic RDP security layer is activate encrypt
        ///            else pass to upper layer
        /// @param data: {Type | Tuple}
        void send(Buffer *data);

        /// @summary: explicit send flag method for particular packet
        ///             (info packet or license packet)
        ///             If encryption is enable apply it
        /// @param flag: {integer} security flag
        /// @param data : {Type | Tuple}
        void sendFlagged(uint16_t flag, Buffer *data);

        /// @summary: Call when fast path packet is received
        /// @param secFlag: {SecFlags}
        /// @param fastPathS : {Buffer}
        void recvFastPath(uint16_t secFlag, Buffer *data);

        /// @summary: Send fastPathS Type as fast path packet
        /// @param secFlag: {SecFlags}
        /// @param fastPathS : {Buffer} type transform to stream and send as fastpath
        void sendFastPath(uint16_t secFlag, Buffer *data);

        /// @return: {integer} mcs user id
        /// @see: mcs.IGCCConfig
        uint16_t getUserId();

        /// @return: {integer} return channel id of proxy
        /// @see: mcs.IGCCConfig
        uint16_t getChannelId();

        /// @return: {gcc.Settings} mcs layer gcc client settings
        /// @see: mcs.IGCCConfig
        ClientSettings &getGCCClientSettings();

        /// @return: {gcc.Settings} mcs layer gcc server settings
        /// @see: mcs.IGCCConfig
        ServerSettings &getGCCServerSettings();

        RDPInfo &info() { return _info; }

        // Enable Secure Mac generation
        bool _enableSecureCheckSum;

    protected:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(SecLayer);

        MCSProxySender *transport();
		bool security_mac_signature(const uint8_t* data, uint32_t length, uint8_t* output);
		bool security_salted_mac_signature(const uint8_t* data, uint32_t length, bool encryption, uint8_t* output);
		bool security_establish_keys(const uint8_t* client_random, const uint8_t* server_random);
		bool security_key_update(uint8_t* key, uint8_t* update_key, int key_len);
		bool security_encrypt(uint8_t* data, int length);
		bool security_decrypt(uint8_t* data, int length);
		bool security_hmac_signature(const uint8_t* data, int length, uint8_t* output);
		bool security_fips_encrypt(uint8_t* data, int length);
		bool security_fips_decrypt(uint8_t* data, int length);
		bool security_fips_check_signature(const uint8_t* data, int length, const uint8_t* sig);

		bool encrypt(Buffer *s, bool saltedMacGeneration);
		bool decrypt(Buffer *s, bool saltedMacGeneration);

        // credentials
        RDPInfo _info;
		bool _serverMode;
        // True if classic encryption is enable
        bool _enableEncryption;
		uint32_t _encryptionMethods;
		
		Rc4 _rc4_decrypt_key;
		int _decrypt_use_count;
		int _decrypt_checksum_use_count;
		Rc4 _rc4_encrypt_key;
		int _encrypt_use_count;
		int _encrypt_checksum_use_count;

		uint8_t _sign_key[16];
		uint8_t _decrypt_key[16];
		uint8_t _encrypt_key[16];
		uint8_t _decrypt_update_key[16];
		uint8_t _encrypt_update_key[16];
		int _rc4_key_len;

		uint8_t _fips_sign_key[20];
		uint8_t _fips_encrypt_key[24];
		uint8_t _fips_decrypt_key[24];
		Cipher _fips_encrypt;
		Cipher _fips_decrypt;
    };

    /// @summary: Client side of security layer
    class ClientSecLayer : public SecLayer
    {
    public:
        ClientSecLayer(Layer *presentation, FastPathLayer *fastPathListener);

        /// @summary: send client random if needed and send info packet
        void connect();

        /// @summary: send information packet(with credentials)
        ///             next state->recvLicenceInfo
        void sendInfoPkt();

        /// @summary: generate and send client random and init session keys 
        void sendClientRandom();

        /// @summary: Read license info packet and check if is a valid client info
        /// Wait Demand Active PDU
        /// @param s: Buffer
        void recvLicenceInfo(Buffer *data);

        shared_ptr<LicenseManager> licenceManager() { return _licenceManager; }
    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ClientSecLayer);

        shared_ptr<LicenseManager> _licenceManager;
        Buffer _pubKeyN, _pubKeyE;
    };

    /// @summary: Server side of security layer
    class ServerSecLayer : public SecLayer
    {
    public:

        /// @param presentation: {Layer}
        ServerSecLayer(Layer *presentation, FastPathLayer *fastPathListener);

        /// @summary: init automata to wait info packet
        void connect();

        ///  @summary: generate proprietary certificate from rsa public key
        bool getCertificate(ServerCertificate &certificate);

        /// @summary: receive client random and generate session keys
        /// @param s: {Buffer}
        void recvClientRandom(Buffer *s);

        /// @summary: receive info packet from client
        /// Client credentials
        /// Send License valid error message
        /// Send Demand Active PDU
        /// Wait Confirm Active PDU
        /// @param s: {Buffer}
        void recvInfoPkt(Buffer *s);

        /// @summary: Send a licensing error data
        void sendLicensingErrorMessage();

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(ServerSecLayer);

        Buffer _rsaN, _rsaE, _rsaD; // RSA Keypair
    };

} // namespace rdpp

#endif // _RDPP_RDP_SEC_H_
