#include <rdp/t125/gcc.h>
#include <core/per.h>
#include <core/log.h>

#define TAG "GCC"

using namespace rdpp;

static const uint8_t t124_02_98_oid[6] = { 0, 0, 20, 124, 0, 1 };
static const string h221_cs_key("Duca");
static const string h221_sc_key("McDn");

ClientCoreData::ClientCoreData()
{
    rdpVersion = RDP_VERSION_5_PLUS;
    desktopWidth = 1280;
    desktopHeight = 800;
    colorDepth = RNS_UD_COLOR_8BPP;
    sasSequence = RNS_UD_SAS_DEL;
    kbdLayout = KBD_LAYOUT_US;
    clientBuild = 3790;
    string _clientName(utf::ascii_to_unicode("rdpp"));
    memset(clientName, 0, sizeof(clientName));
    memcpy(clientName, _clientName.c_str(), _clientName.length());
    keyboardType = IBM_101_102_KEYS;
    keyboardSubType = 0;
    keyboardFnKeys = 12;

    memset(imeFileName, 0, sizeof(imeFileName));
    postBeta2ColorDepth = RNS_UD_COLOR_8BPP;
    clientProductId = 1;
    serialNumber = 0;
    highColorDepth = HIGH_COLOR_24BPP;
    supportedColorDepths = RNS_UD_15BPP_SUPPORT | RNS_UD_16BPP_SUPPORT | RNS_UD_24BPP_SUPPORT | RNS_UD_32BPP_SUPPORT;
    earlyCapabilityFlags = RNS_UD_CS_SUPPORT_ERRINFO_PDU;

    memset(clientDigProductId, 0, sizeof(clientDigProductId));
    
	connectionType = 0;
    pad1octet = 0;
    serverSelectedProtocol = 0;
}

bool ClientSettings::readConferenceCreateRequest(Buffer *s)
{
    uint8_t choice;
    uint16_t length;
    uint8_t number;
    uint8_t selection;

    if (!PER::readChoice(s, choice) ||
            !PER::readObjectIdentifier(s, t124_02_98_oid) ||
            !PER::readLength(s, length) ||
            !PER::readChoice(s, choice) ||
            !PER::readSelection(s, selection) ||
            !PER::readNumericString(s, 1) ||
            !PER::readPadding(s, 1))
        return false;

    if (!PER::readNumberOfSet(s, number))
        return false;
    if (number != 1) {
        RDPP_LOG(TAG, ERROR) << "Invalid number of set in readConferenceCreateRequest";
        return false;
    }
    if (!PER::readChoice(s, choice))
        return false;
    if (choice != 0xc0) {
        RDPP_LOG(TAG, ERROR) << "Invalid choice in readConferenceCreateRequest";
        return false;
    }
    if (!PER::readOctetStream(s, h221_cs_key, 4))
        return false;
    if (!PER::readLength(s, length))
		return false;

    DataBlock block;
    while (length > sizeof(block)) {
		s->retrieve(&block, sizeof(block));

        switch (block.type) {
        case MSG_TYPE_CS_CORE:
			RDPP_LOG(TAG, TRACE) << "Read Settings: CS_CORE(" << block.length << ")";
            memcpy(&core, s->data(), MIN((block.length - sizeof(block)), sizeof(core)));
			s->retrieve(block.length - sizeof(block));
            break;
        case MSG_TYPE_CS_NET:
			RDPP_LOG(TAG, TRACE) << "Read Settings: CS_NET(" << block.length << ")";
            network.read(s);
            break;
        case MSG_TYPE_CS_SECURITY:
			RDPP_LOG(TAG, TRACE) << "Read Settings: CS_SECURITY(" << block.length << ")";
            s->retrieve(&security, sizeof(ClientSecurityData));
            break;
		default:
			RDPP_LOG(TAG, TRACE) << "Read Settings: " << (void *)block.type << "(" << block.length << ")";
			s->retrieve(block.length - sizeof(block));
			break;
        }
        length -= block.length;
    }

   return true;
}

void ClientSettings::writeConferenceCreateRequest(Buffer *s)
{
    Buffer settings;
	DataBlock::write(&settings, MSG_TYPE_CS_CORE, sizeof(ClientCoreData));
    settings.append(&core, sizeof(ClientCoreData));
	DataBlock::write(&settings, MSG_TYPE_CS_NET, network.size());
    network.write(&settings);
	DataBlock::write(&settings, MSG_TYPE_CS_SECURITY, sizeof(ClientSecurityData));
    settings.append(&security, sizeof(ClientSecurityData));

    PER::writeChoice(s, 0);
    PER::writeObjectIdentifier(s, t124_02_98_oid);
    PER::writeLength(s, settings.length() + 14);
    PER::writeChoice(s, 0);
    PER::writeSelection(s, 0x80);
    PER::writeNumericString(s, "1", 1);
    PER::writePadding(s, 1);
    PER::writeNumberOfSet(s, 1);
    PER::writeChoice(s, 0xc0);
    PER::writeOctetStream(s, h221_cs_key, 4);
    PER::writeOctetStream(s, settings.retrieveAllAsString());
}

bool ServerSettings::readConferenceCreateResponse(Buffer *s)
{
    uint8_t choice;
    uint16_t length;
    uint16_t integer16;
    uint32_t integer32;
    uint8_t enumerated;
    uint8_t number;

    if (!PER::readChoice(s, choice) ||
			!PER::readObjectIdentifier(s, t124_02_98_oid) ||
			!PER::readLength(s, length) ||
			!PER::readChoice(s, choice) ||
			!PER::readInteger16(s, integer16, 1001) ||
			!PER::readInteger(s, integer32) ||
			!PER::readEnumerates(s, enumerated) ||
			!PER::readNumberOfSet(s, number) ||
			!PER::readChoice(s, choice))
		return false;

    if (!PER::readOctetStream(s, h221_sc_key, 4)) {
		RDPP_LOG(TAG, ERROR) << "cannot read h221_sc_key";
        return false;
	}

    PER::readLength(s, length);

    DataBlock block;
    while (length > sizeof(block)) {
        s->retrieve(&block, sizeof(block));

        switch (block.type) {
        case MSG_TYPE_SC_CORE:
			s->retrieve(&core, block.length - sizeof(block));
            break;
        case MSG_TYPE_SC_NET:
			RDPP_LOG(TAG, TRACE) << "Read Settings: CS_NET(" << block.length << ")";
            network.read(s);
            break;
        case MSG_TYPE_SC_SECURITY:
			RDPP_LOG(TAG, TRACE) << "Read Settings: CS_SECURITY(" << block.length << ")";
            security.read(s);
            break;
		default:
			RDPP_LOG(TAG, WARN) << "Read Settings: Unknown(type=" << block.type << ", length=" << block.length << ")";
			s->retrieve(block.length - sizeof(block));
			break;
        }
        length -= block.length;
    }
    return true;
}

void ServerSettings::writeConferenceCreateResponse(Buffer *s)
{
    Buffer settings;
	
	DataBlock::write(&settings, MSG_TYPE_SC_CORE, sizeof(ServerCoreData));
    settings.append(&core, sizeof(ServerCoreData));
	DataBlock::write(&settings, MSG_TYPE_SC_NET, network.size());
    network.write(&settings);
	DataBlock::write(&settings, MSG_TYPE_SC_SECURITY, security.size());
    security.write(&settings);
	
    PER::writeChoice(s, 0);
    PER::writeObjectIdentifier(s, t124_02_98_oid);
    PER::writeLength(s, settings.length() + 14);
    PER::writeChoice(s, 0x14);
    PER::writeInteger16(s, 0x79F3, 1001);
    PER::writeInteger(s, 1);
    PER::writeEnumerates(s, 0);
    PER::writeNumberOfSet(s, 1);
    PER::writeChoice(s, 0xc0);
    PER::writeOctetStream(s, h221_sc_key, 4);
    PER::writeOctetStream(s, settings.retrieveAllAsString());
}
