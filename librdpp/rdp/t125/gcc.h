/**
 * Implement GCC structure use in RDP protocol
 * http://msdn.microsoft.com/en-us/library/cc240508.aspx
 */

#ifndef _RDPP_RDP_T125_GCC_H_
#define _RDPP_RDP_T125_GCC_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/string_util.h>
#include <core/unicode/utf.h>
#include <rdp/t125/certificate.h>
#include <vector>

namespace rdpp {

#include <core/pshpack1.h>

    /// @summary: Server to Client block
    /// GCC conference messages
    /// @see: http://msdn.microsoft.com/en-us/library/cc240509.aspx
    enum GCCMessageType
    {
        // server->client
        MSG_TYPE_SC_CORE = 0x0C01,
        MSG_TYPE_SC_SECURITY = 0x0C02,
        MSG_TYPE_SC_NET = 0x0C03,
        // client->server
        MSG_TYPE_CS_CORE = 0xC001,
        MSG_TYPE_CS_SECURITY = 0xC002,
        MSG_TYPE_CS_NET = 0xC003,
        MSG_TYPE_CS_CLUSTER = 0xC004,
        MSG_TYPE_CS_MONITOR = 0xC005,
    };

    /// @summary: Depth color
    /// @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    enum ColorDepth
    {
        RNS_UD_COLOR_8BPP = 0xCA01,
        RNS_UD_COLOR_16BPP_555 = 0xCA02,
        RNS_UD_COLOR_16BPP_565 = 0xCA03,
        RNS_UD_COLOR_24BPP = 0xCA04,
    };

    /// @summary: High color of client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    enum HighColor
    {
        HIGH_COLOR_4BPP = 0x0004,
        HIGH_COLOR_8BPP = 0x0008,
        HIGH_COLOR_15BPP = 0x000f,
        HIGH_COLOR_16BPP = 0x0010,
        HIGH_COLOR_24BPP = 0x0018,
    };

    /// @summary: Supported depth flag
    /// @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    enum Support
    {
        RNS_UD_24BPP_SUPPORT = 0x0001,
        RNS_UD_16BPP_SUPPORT = 0x0002,
        RNS_UD_15BPP_SUPPORT = 0x0004,
        RNS_UD_32BPP_SUPPORT = 0x0008,
    };

    /// @summary: For more details on each flags click above
    /// @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    enum CapabilityFlags
    {
        RNS_UD_CS_SUPPORT_ERRINFO_PDU = 0x0001,
        RNS_UD_CS_WANT_32BPP_SESSION = 0x0002,
        RNS_UD_CS_SUPPORT_STATUSINFO_PDU = 0x0004,
        RNS_UD_CS_STRONG_ASYMMETRIC_KEYS = 0x0008,
        RNS_UD_CS_UNUSED = 0x0010,
        RNS_UD_CS_VALID_CONNECTION_TYPE = 0x0020,
        RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU = 0x0040,
        RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT = 0x0080,
        RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL = 0x0100,
        RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE = 0x0200,
        RNS_UD_CS_SUPPORT_HEARTBEAT_PDU = 0x0400,
    };

    /// @summary: This information is correct if
    /// RNS_UD_CS_VALID_CONNECTION_TYPE flag is set on capabilityFlag
    /// @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    enum ConnectionType
    {
        CONNECTION_TYPE_MODEM = 0x01,
        CONNECTION_TYPE_BROADBAND_LOW = 0x02,
        CONNECTION_TYPE_SATELLITE = 0x03,
        CONNECTION_TYPE_BROADBAND_HIGH = 0x04,
        CONNECTION_TYPE_WAN = 0x05,
        CONNECTION_TYPE_LAN = 0x06,
        CONNECTION_TYPE_AUTODETECT = 0x07,
    };

    /// @summary: Supported version of RDP
    /// @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    enum RDPVersion
    {
        RDP_VERSION_4 = 0x00080001,
        RDP_VERSION_5_PLUS = 0x00080004,
    };

    enum Sequence
    {
        RNS_UD_SAS_DEL = 0xAA03,
    };

    /// @summary: Encryption methods supported
    /// @see: http://msdn.microsoft.com/en-us/library/cc240511.aspx
    enum EncryptionMethod
    {
        ENCRYPTION_METHOD_40BIT = 0x00000001,
        ENCRYPTION_METHOD_128BIT = 0x00000002,
        ENCRYPTION_METHOD_56BIT = 0x00000008,
        ENCRYPTION_METHOD_FIPS = 0x00000010,
    };

    /// @summary: level of 'security'
    /// @see: http://msdn.microsoft.com/en-us/library/cc240518.aspx
    enum EncryptionLevel
    {
        ENCRYPTION_LEVEL_NONE = 0x00000000,
        ENCRYPTION_LEVEL_LOW = 0x00000001,
        ENCRYPTION_LEVEL_CLIENT_COMPATIBLE = 0x00000002,
        ENCRYPTION_LEVEL_HIGH = 0x00000003,
        ENCRYPTION_LEVEL_FIPS = 0x00000004,
    };

    /// @summary: Channel options
    /// @see: http://msdn.microsoft.com/en-us/library/cc240513.aspx
    enum ChannelOptions
    {
        CHANNEL_OPTION_INITIALIZED = 0x80000000,
        CHANNEL_OPTION_ENCRYPT_RDP = 0x40000000,
        CHANNEL_OPTION_ENCRYPT_SC = 0x20000000,
        CHANNEL_OPTION_ENCRYPT_CS = 0x10000000,
        CHANNEL_OPTION_PRI_HIGH = 0x08000000,
        CHANNEL_OPTION_PRI_MED = 0x04000000,
        CHANNEL_OPTION_PRI_LOW = 0x02000000,
        CHANNEL_OPTION_COMPRESS_RDP = 0x00800000,
        CHANNEL_OPTION_COMPRESS = 0x00400000,
        CHANNEL_OPTION_SHOW_PROTOCOL = 0x00200000,
        REMOTE_CONTROL_PERSISTENT = 0x00100000,
    };

    /// @summary: Keyboard type
    /// @see: IBM_101_102_KEYS is the most common keyboard type
    enum KeyboardType
    {
        IBM_PC_XT_83_KEY = 0x00000001,
        OLIVETTI = 0x00000002,
        IBM_PC_AT_84_KEY = 0x00000003,
        IBM_101_102_KEYS = 0x00000004,
        NOKIA_1050 = 0x00000005,
        NOKIA_9140 = 0x00000006,
        JAPANESE = 0x00000007,
    };

    /// @summary: Keyboard layout definition
    /// @see: http://technet.microsoft.com/en-us/library/cc766503%28WS.10%29.aspx
    enum KeyboardLayout
    {
        KBD_LAYOUT_ARABIC = 0x00000401,
        KBD_LAYOUT_BULGARIAN = 0x00000402,
        KBD_LAYOUT_CHINESE_US_KEYBOARD = 0x00000404,
        KBD_LAYOUT_CZECH = 0x00000405,
        KBD_LAYOUT_DANISH = 0x00000406,
        KBD_LAYOUT_GERMAN = 0x00000407,
        KBD_LAYOUT_GREEK = 0x00000408,
        KBD_LAYOUT_US = 0x00000409,
        KBD_LAYOUT_SPANISH = 0x0000040a,
        KBD_LAYOUT_FINNISH = 0x0000040b,
        KBD_LAYOUT_FRENCH = 0x0000040c,
        KBD_LAYOUT_HEBREW = 0x0000040d,
        KBD_LAYOUT_HUNGARIAN = 0x0000040e,
        KBD_LAYOUT_ICELANDIC = 0x0000040f,
        KBD_LAYOUT_ITALIAN = 0x00000410,
        KBD_LAYOUT_JAPANESE = 0x00000411,
        KBD_LAYOUT_KOREAN = 0x00000412,
        KBD_LAYOUT_DUTCH = 0x00000413,
        KBD_LAYOUT_NORWEGIAN = 0x00000414,
    };

    /// @summary: GCC user data block header
    /// @see: https://msdn.microsoft.com/en-us/library/cc240509.aspx
    struct DataBlock {
        uint16_t type;
        uint16_t length;

		static void write(Buffer *s, uint16_t type, uint16_t blockLength)
		{
			s->appendUInt16(type);
			s->appendUInt16(blockLength + 4);
		}
    };

    /// @summary: Class that represent core setting of client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240510.aspx
    struct ClientCoreData {
        uint32_t rdpVersion;
        uint16_t desktopWidth;
        uint16_t desktopHeight;
        uint16_t colorDepth;
        uint16_t sasSequence;
        uint32_t kbdLayout;
        uint32_t clientBuild;
        uint16_t clientName[16]; // unicode
        uint32_t keyboardType;
        uint32_t keyboardSubType;
        uint32_t keyboardFnKeys;

        // optional
        char imeFileName[64];
        uint16_t postBeta2ColorDepth;
        uint16_t clientProductId;
        uint32_t serialNumber;
        uint16_t highColorDepth;
        uint16_t supportedColorDepths;
        uint16_t earlyCapabilityFlags;
        char clientDigProductId[64];
        uint8_t connectionType;
        uint8_t pad1octet;
        uint32_t serverSelectedProtocol;

        ClientCoreData();

		void setClientName(const string &name)
		{
			string _name(utf::ascii_to_unicode(name).substr(0, 15)); // unicode
			memset(clientName, 0, sizeof(clientName));
			memcpy(clientName, _name.c_str(), _name.length());
		}
		string getClientName()
		{
			string _clientName;
			for (int i = 0; i < 16; ++i) {
				if (clientName[i] != 0)
					_clientName.append((char *)&(clientName[i]), 2);
			}
			
			return utf::unicode_to_ascii(_clientName);
		}
    };

    /// @summary: Server side core settings structure
    /// @see: http://msdn.microsoft.com/en-us/library/cc240517.aspx
    struct ServerCoreData {
        uint32_t rdpVersion;
        uint32_t clientRequestedProtocol;
        uint32_t earlyCapabilityFlags;

        ServerCoreData() 
            : rdpVersion(RDP_VERSION_5_PLUS), clientRequestedProtocol(0), earlyCapabilityFlags(0)
        {}
    };

    /// @summary: Client security setting
    /// @see: http://msdn.microsoft.com/en-us/library/cc240511.aspx
    struct ClientSecurityData {
        uint32_t encryptionMethods;
        uint32_t extEncryptionMethods;

        ClientSecurityData()
			: extEncryptionMethods(0)
            , encryptionMethods(ENCRYPTION_METHOD_40BIT | ENCRYPTION_METHOD_56BIT | ENCRYPTION_METHOD_128BIT)
        {}
    };

    /// @summary: Server security settings
    /// @see: http://msdn.microsoft.com/en-us/library/cc240518.aspx
    struct ServerSecurityData {
        uint32_t encryptionMethod;
        uint32_t encryptionLevel;

        // optional
        uint32_t serverRandomLen;
        uint32_t serverCertLen;
        Buffer serverRandom;
        ServerCertificate serverCertificate;

        ServerSecurityData() : encryptionMethod(0), encryptionLevel(0) {}
        void read(Buffer *s)
        {
            encryptionMethod = s->readUInt32();
            encryptionLevel = s->readUInt32();

            if (encryptionMethod != 0 || encryptionLevel != 0) {
                serverRandomLen = s->readUInt32();
                serverCertLen = s->readUInt32();
                s->retrieve(serverRandom, serverRandomLen);
                serverCertificate.read(s);
            }
        }
        void write(Buffer *s)
        {
			assert(serverRandomLen == serverRandom.length());
			assert(serverCertLen == serverCertificate.size());

            s->appendUInt32(encryptionMethod);
            s->appendUInt32(encryptionLevel);

            if (encryptionMethod != 0 || encryptionLevel != 0) {
                s->appendUInt32(serverRandomLen);
                s->appendUInt32(serverCertLen);
                s->append(serverRandom);
                serverCertificate.write(s);
            }
        }
		uint16_t size()
		{
			if (encryptionMethod != 0 || encryptionLevel != 0) {
				return 16 + serverRandom.length() + serverCertificate.size();
			} else {
				return 8;
			}
		}
    };

    /// Channels structure share between client and server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240513.aspx
    struct ChannelDef {
        char name[8];
        uint32_t options;

        ChannelDef() : options(0)
        {
            memset(name, 0, sizeof(name));
        }
    };


    /// @summary: GCC client network block
    /// All channels asked by client are listed here
    /// @see: http://msdn.microsoft.com/en-us/library/cc240512.aspx
    struct ClientNetworkData
    {
        uint32_t channelCount;
        std::vector<shared_ptr<ChannelDef>> channelDefArray;

        ClientNetworkData() : channelCount(0) {}
        void read(Buffer *s)
        {
            channelCount = s->readUInt32();
            for (size_t i = 0; i < channelCount; ++i) {
                shared_ptr<ChannelDef> def(new ChannelDef);

                s->retrieve(def.get(), sizeof(ChannelDef));
                channelDefArray.push_back(def);
            }
        }
        void write(Buffer *s)
        {
			assert(channelCount == channelDefArray.size());

            s->appendUInt32(channelCount);
            for (size_t i = 0; i < channelCount; ++i)
                s->append(channelDefArray[i].get(), sizeof(ChannelDef));
        }
		uint16_t size()
		{
			assert(channelCount == channelDefArray.size());

			uint16_t len = sizeof(channelCount);
			for (size_t i = 0; i < channelCount; ++i)
				len += sizeof(ChannelDef);
			return len;
		}
    };

    /// @summary: GCC server network block
    /// All channels asked by client are listed here
    /// @see: All channels asked by client are listed here
    struct ServerNetworkData
    {
        uint16_t MCSChannelId;
        uint16_t channelCount;
        std::vector<uint16_t> channelIdArray;
        uint16_t pad;  // if ((channelCount % 2) == 1)

        ServerNetworkData() 
			: MCSChannelId(1003) // MCS_GLOBAL_CHANNEL
			, channelCount(0), pad(0)
		{}
        void read(Buffer *s)
        {
            MCSChannelId = s->readUInt16();
            channelCount = s->readUInt16();

            for (size_t i = 0; i < channelCount; ++i)
                channelIdArray.push_back(s->readUInt16());
            // pad
            if ((channelCount % 2) == 1)
                s->readUInt16();
        }

        void write(Buffer *s)
        {
			assert(channelCount == channelIdArray.size());

            s->appendUInt16(MCSChannelId);
            s->appendUInt16(channelCount);
            for (size_t i = 0; i < channelCount; ++i)
                s->appendUInt16(channelIdArray[i]);
            // pad
            if ((channelCount % 2) == 1)
                s->appendUInt16(0);
        }
		uint16_t size()
		{
			assert(channelCount == channelIdArray.size());

			uint16_t len = 4;
			for (size_t i = 0; i < channelCount; ++i)
				len += 2;
			if ((channelCount % 2) == 1)
				len += 2;
			return len;
		}
    };

    /// https://msdn.microsoft.com/en-us/library/cc240509.aspx
    class ClientSettings
    {
    public:
        ClientCoreData core;
        ClientNetworkData network;
        ClientSecurityData security;

        /// @summary: Read a response from client
        /// GCC create request
        /// @param s: Buffer
        /// @return client settings(Settings)
        bool readConferenceCreateRequest(Buffer *s);

        /// @summary: Write conference create request structure
        /// @param userData: Settings for client
        /// @return: GCC packet
        void writeConferenceCreateRequest(Buffer *s);
    };

    class ServerSettings
    {
    public:
        ServerCoreData core;
        ServerNetworkData network;
        ServerSecurityData security;

        /// @summary: Read response from server
        /// and return server settings read from this response
        /// @param s: Buffer
        /// @return: ServerSettings
        bool readConferenceCreateResponse(Buffer *s);


        /// @summary: Write a conference create response packet
        /// @param serverData: Settings for server
        /// @return: gcc packet
        void writeConferenceCreateResponse(Buffer *s);
    };

#include <core/poppack.h>

} // namespace rdpp

#endif // _RDPP_RDP_T125_GCC_H_
