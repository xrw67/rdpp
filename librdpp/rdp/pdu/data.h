/**
 * Implement the main graphic layer
 *
 * In this layer are managed all mains bitmap update orders end user inputs
 */
#ifndef _RDPP_RDP_PDU_DATA_H_
#define _RDPP_RDP_PDU_DATA_H_

#include <core/config.h>
#include <core/buffer.h>
#include <rdp/pdu/caps.h>
#include <rdp/pdu/order.h>
#include <vector>

namespace rdpp {

#include <core/pshpack1.h>

    /// @summary: Data PDU type primary index
    /// @see: http://msdn.microsoft.com/en-us/library/cc240576.aspx
    enum PDUType {
        PDUTYPE_DEMANDACTIVEPDU = 0x11,
        PDUTYPE_CONFIRMACTIVEPDU = 0x13,
        PDUTYPE_DEACTIVATEALLPDU = 0x16,
        PDUTYPE_DATAPDU = 0x17,
        PDUTYPE_SERVER_REDIR_PKT = 0x1A,
    };

    /// @summary: Data PDU type secondary index
    /// @see: http://msdn.microsoft.com/en-us/library/cc240577.aspx
    enum PDUType2 {
        PDUTYPE2_UPDATE = 0x02,
        PDUTYPE2_CONTROL = 0x14,
        PDUTYPE2_POINTER = 0x1B,
        PDUTYPE2_INPUT = 0x1C,
        PDUTYPE2_SYNCHRONIZE = 0x1F,
        PDUTYPE2_REFRESH_RECT = 0x21,
        PDUTYPE2_PLAY_SOUND = 0x22,
        PDUTYPE2_SUPPRESS_OUTPUT = 0x23,
        PDUTYPE2_SHUTDOWN_REQUEST = 0x24,
        PDUTYPE2_SHUTDOWN_DENIED = 0x25,
        PDUTYPE2_SAVE_SESSION_INFO = 0x26,
        PDUTYPE2_FONTLIST = 0x27,
        PDUTYPE2_FONTMAP = 0x28,
        PDUTYPE2_SET_KEYBOARD_INDICATORS = 0x29,
        PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST = 0x2B,
        PDUTYPE2_BITMAPCACHE_ERROR_PDU = 0x2C,
        PDUTYPE2_SET_KEYBOARD_IME_STATUS = 0x2D,
        PDUTYPE2_OFFSCRCACHE_ERROR_PDU = 0x2E,
        PDUTYPE2_SET_ERROR_INFO_PDU = 0x2F,
        PDUTYPE2_DRAWNINEGRID_ERROR_PDU = 0x30,
        PDUTYPE2_DRAWGDIPLUS_ERROR_PDU = 0x31,
        PDUTYPE2_ARC_STATUS_PDU = 0x32,
        PDUTYPE2_STATUS_INFO_PDU = 0x36,
        PDUTYPE2_MONITOR_LAYOUT_PDU = 0x37,
    };

    /// @summary: Buffer priority
    /// @see: http://msdn.microsoft.com/en-us/library/cc240577.aspx
    enum StreamId {
        STREAM_UNDEFINED = 0x00,
        STREAM_LOW = 0x01,
        STREAM_MED = 0x02,
        STREAM_HI = 0x04,
    };

    /// @summary: PDU compression order
    /// @see: http://msdn.microsoft.com/en-us/library/cc240577.aspx
    enum CompressionOrder {
        CompressionTypeMask = 0x0F,
        PACKET_COMPRESSED = 0x20,
        PACKET_AT_FRONT = 0x40,
        PACKET_FLUSHED = 0x80,
    };

    /// @summary: PDU compression type
    /// @see: http://msdn.microsoft.com/en-us/library/cc240577.aspx
    enum CompressionType {
        PACKET_COMPR_TYPE_8K = 0x0,
        PACKET_COMPR_TYPE_64K = 0x1,
        PACKET_COMPR_TYPE_RDP6 = 0x2,
        PACKET_COMPR_TYPE_RDP61 = 0x3,
    };

    /// @summary: Action flag use in Control PDU packet
    /// @see: http://msdn.microsoft.com/en-us/library/cc240492.aspx
    enum Action {
        CTRLACTION_REQUEST_CONTROL = 0x0001,
        CTRLACTION_GRANTED_CONTROL = 0x0002,
        CTRLACTION_DETACH = 0x0003,
        CTRLACTION_COOPERATE = 0x0004,
    };

    /// @summary: Use to determine the number of persistent key packet
    /// @see: http://msdn.microsoft.com/en-us/library/cc240495.aspx
    enum PersistentKeyListFlag {
        PERSIST_FIRST_PDU = 0x01,
        PERSIST_LAST_PDU = 0x02,
    };

    /// @summary: Use in bitmap update PDU
    /// @see: http://msdn.microsoft.com/en-us/library/cc240612.aspx
    enum BitmapFlag {
        BITMAP_COMPRESSION = 0x0001,
        BITMAP_NO_COMPRESSION_HDR = 0x0400,
    };

    /// @summary: Use in update PDU to determine which type of update
    /// @see: http://msdn.microsoft.com/en-us/library/cc240608.aspx
    enum UpdateType {
        UPDATETYPE_ORDERS = 0x0000,
        UPDATETYPE_BITMAP = 0x0001,
        UPDATETYPE_PALETTE = 0x0002,
        UPDATETYPE_SYNCHRONIZE = 0x0003,
    };

    /// @summary: Use in slow - path input PDU
    /// @see: http://msdn.microsoft.com/en-us/library/cc240583.aspx
    enum InputMessageType {
        INPUT_EVENT_SYNC = 0x0000,
        INPUT_EVENT_UNUSED = 0x0002,
        INPUT_EVENT_SCANCODE = 0x0004,
        INPUT_EVENT_UNICODE = 0x0005,
        INPUT_EVENT_MOUSE = 0x8001,
        INPUT_EVENT_MOUSEX = 0x8002,
    };

    /// @summary: Use in Pointer event
    /// @see: http://msdn.microsoft.com/en-us/library/cc240586.aspx
    enum PointerFlag {
        PTRFLAGS_HWHEEL = 0x0400,
        PTRFLAGS_WHEEL = 0x0200,
        PTRFLAGS_WHEEL_NEGATIVE = 0x0100,
        WheelRotationMask = 0x01FF,
        PTRFLAGS_MOVE = 0x0800,
        PTRFLAGS_DOWN = 0x8000,
        PTRFLAGS_BUTTON1 = 0x1000,
        PTRFLAGS_BUTTON2 = 0x2000,
        PTRFLAGS_BUTTON3 = 0x4000,
    };

    /// @summary: Use in scan code key event
    /// @see: http://msdn.microsoft.com/en-us/library/cc240584.aspx
    enum KeyboardFlag {
        KBDFLAGS_EXTENDED = 0x0100,
        KBDFLAGS_DOWN = 0x4000,
        KBDFLAGS_RELEASE = 0x8000,
    };

    /// @summary: Use in Fast Path update packet
    /// @see: http://msdn.microsoft.com/en-us/library/cc240622.aspx
    enum FastPathUpdateType {
        FASTPATH_UPDATETYPE_ORDERS = 0x0,
        FASTPATH_UPDATETYPE_BITMAP = 0x1,
        FASTPATH_UPDATETYPE_PALETTE = 0x2,
        FASTPATH_UPDATETYPE_SYNCHRONIZE = 0x3,
        FASTPATH_UPDATETYPE_SURFCMDS = 0x4,
        FASTPATH_UPDATETYPE_PTR_NULL = 0x5,
        FASTPATH_UPDATETYPE_PTR_DEFAULT = 0x6,
        FASTPATH_UPDATETYPE_PTR_POSITION = 0x8,
        FASTPATH_UPDATETYPE_COLOR = 0x9,
        FASTPATH_UPDATETYPE_CACHED = 0xA,
        FASTPATH_UPDATETYPE_POINTER = 0xB,
    };

    /// @summary: Flag for compression
    /// @see: http://msdn.microsoft.com/en-us/library/cc240622.aspx
    enum FastPathOutputCompression {
        FASTPATH_OUTPUT_COMPRESSION_USED = 0x2,
    };

    /// @summary: Use in supress output PDU
    /// @see: http://msdn.microsoft.com/en-us/library/cc240648.aspx
    enum Display {
        SUPPRESS_DISPLAY_UPDATES = 0x00,
        ALLOW_DISPLAY_UPDATES = 0x01,
    };

    /// @summary: Use to known state of keyboard
    /// @see: https://msdn.microsoft.com/en-us/library/cc240588.aspx
    enum ToogleFlag {
        TS_SYNC_SCROLL_LOCK = 0x00000001,
        TS_SYNC_NUM_LOCK = 0x00000002,
        TS_SYNC_CAPS_LOCK = 0x00000004,
        TS_SYNC_KANA_LOCK = 0x00000008,
    };

    /// @summary: Error code use in Error info PDU
    /// @see: http://msdn.microsoft.com/en-us/library/cc240544.aspx
    enum ErrorInfo {
        ERRINFO_RPC_INITIATED_DISCONNECT = 0x00000001,
        ERRINFO_RPC_INITIATED_LOGOFF = 0x00000002,
        ERRINFO_IDLE_TIMEOUT = 0x00000003,
        ERRINFO_LOGON_TIMEOUT = 0x00000004,
        ERRINFO_DISCONNECTED_BY_OTHERCONNECTION = 0x00000005,
        ERRINFO_OUT_OF_MEMORY = 0x00000006,
        ERRINFO_SERVER_DENIED_CONNECTION = 0x00000007,
        ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES = 0x00000009,
        ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED = 0x0000000A,
        ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER = 0x0000000B,
        ERRINFO_LOGOFF_BY_USER = 0x0000000C,
        ERRINFO_LICENSE_INTERNAL = 0x00000100,
        ERRINFO_LICENSE_NO_LICENSE_SERVER = 0x00000101,
        ERRINFO_LICENSE_NO_LICENSE = 0x00000102,
        ERRINFO_LICENSE_BAD_CLIENT_MSG = 0x00000103,
        ERRINFO_LICENSE_HWID_DOESNT_MATCH_LICENSE = 0x00000104,
        ERRINFO_LICENSE_BAD_CLIENT_LICENSE = 0x00000105,
        ERRINFO_LICENSE_CANT_FINISH_PROTOCOL = 0x00000106,
        ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL = 0x00000107,
        ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION = 0x00000108,
        ERRINFO_LICENSE_CANT_UPGRADE_LICENSE = 0x00000109,
        ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS = 0x0000010A,
        ERRINFO_CB_DESTINATION_NOT_FOUND = 0x0000400,
        ERRINFO_CB_LOADING_DESTINATION = 0x0000402,
        ERRINFO_CB_REDIRECTING_TO_DESTINATION = 0x0000404,
        ERRINFO_CB_SESSION_ONLINE_VM_WAKE = 0x0000405,
        ERRINFO_CB_SESSION_ONLINE_VM_BOOT = 0x0000406,
        ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS = 0x0000407,
        ERRINFO_CB_DESTINATION_POOL_NOT_FREE = 0x0000408,
        ERRINFO_CB_CONNECTION_CANCELLED = 0x0000409,
        ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS = 0x0000410,
        ERRINFO_CB_SESSION_ONLINE_VM_BOOT_TIMEOUT = 0x0000411,
        ERRINFO_CB_SESSION_ONLINE_VM_SESSMON_FAILED = 0x0000412,
        ERRINFO_UNKNOWNPDUTYPE2 = 0x000010C9,
        ERRINFO_UNKNOWNPDUTYPE = 0x000010CA,
        ERRINFO_DATAPDUSEQUENCE = 0x000010CB,
        ERRINFO_CONTROLPDUSEQUENCE = 0x000010CD,
        ERRINFO_INVALIDCONTROLPDUACTION = 0x000010CE,
        ERRINFO_INVALIDINPUTPDUTYPE = 0x000010CF,
        ERRINFO_INVALIDINPUTPDUMOUSE = 0x000010D0,
        ERRINFO_INVALIDREFRESHRECTPDU = 0x000010D1,
        ERRINFO_CREATEUSERDATAFAILED = 0x000010D2,
        ERRINFO_CONNECTFAILED = 0x000010D3,
        ERRINFO_CONFIRMACTIVEWRONGSHAREID = 0x000010D4,
        ERRINFO_CONFIRMACTIVEWRONGORIGINATOR = 0x000010D5,
        ERRINFO_PERSISTENTKEYPDUBADLENGTH = 0x000010DA,
        ERRINFO_PERSISTENTKEYPDUILLEGALFIRST = 0x000010DB,
        ERRINFO_PERSISTENTKEYPDUTOOMANYTOTALKEYS = 0x000010DC,
        ERRINFO_PERSISTENTKEYPDUTOOMANYCACHEKEYS = 0x000010DD,
        ERRINFO_INPUTPDUBADLENGTH = 0x000010DE,
        ERRINFO_BITMAPCACHEERRORPDUBADLENGTH = 0x000010DF,
        ERRINFO_SECURITYDATATOOSHORT = 0x000010E0,
        ERRINFO_VCHANNELDATATOOSHORT = 0x000010E1,
        ERRINFO_SHAREDATATOOSHORT = 0x000010E2,
        ERRINFO_BADSUPRESSOUTPUTPDU = 0x000010E3,
        ERRINFO_CONFIRMACTIVEPDUTOOSHORT = 0x000010E5,
        ERRINFO_CAPABILITYSETTOOSMALL = 0x000010E7,
        ERRINFO_CAPABILITYSETTOOLARGE = 0x000010E8,
        ERRINFO_NOCURSORCACHE = 0x000010E9,
        ERRINFO_BADCAPABILITIES = 0x000010EA,
        ERRINFO_VIRTUALCHANNELDECOMPRESSIONERR = 0x000010EC,
        ERRINFO_INVALIDVCCOMPRESSIONTYPE = 0x000010ED,
        ERRINFO_INVALIDCHANNELID = 0x000010EF,
        ERRINFO_VCHANNELSTOOMANY = 0x000010F0,
        ERRINFO_REMOTEAPPSNOTENABLED = 0x000010F3,
        ERRINFO_CACHECAPNOTSET = 0x000010F4,
        ERRINFO_BITMAPCACHEERRORPDUBADLENGTH2 = 0x000010F5,
        ERRINFO_OFFSCRCACHEERRORPDUBADLENGTH = 0x000010F6,
        ERRINFO_DNGCACHEERRORPDUBADLENGTH = 0x000010F7,
        ERRINFO_GDIPLUSPDUBADLENGTH = 0x000010F8,
        ERRINFO_SECURITYDATATOOSHORT2 = 0x00001111,
        ERRINFO_SECURITYDATATOOSHORT3 = 0x00001112,
        ERRINFO_SECURITYDATATOOSHORT4 = 0x00001113,
        ERRINFO_SECURITYDATATOOSHORT5 = 0x00001114,
        ERRINFO_SECURITYDATATOOSHORT6 = 0x00001115,
        ERRINFO_SECURITYDATATOOSHORT7 = 0x00001116,
        ERRINFO_SECURITYDATATOOSHORT8 = 0x00001117,
        ERRINFO_SECURITYDATATOOSHORT9 = 0x00001118,
        ERRINFO_SECURITYDATATOOSHORT10 = 0x00001119,
        ERRINFO_SECURITYDATATOOSHORT11 = 0x0000111A,
        ERRINFO_SECURITYDATATOOSHORT12 = 0x0000111B,
        ERRINFO_SECURITYDATATOOSHORT13 = 0x0000111C,
        ERRINFO_SECURITYDATATOOSHORT14 = 0x0000111D,
        ERRINFO_SECURITYDATATOOSHORT15 = 0x0000111E,
        ERRINFO_SECURITYDATATOOSHORT16 = 0x0000111F,
        ERRINFO_SECURITYDATATOOSHORT17 = 0x00001120,
        ERRINFO_SECURITYDATATOOSHORT18 = 0x00001121,
        ERRINFO_SECURITYDATATOOSHORT19 = 0x00001122,
        ERRINFO_SECURITYDATATOOSHORT20 = 0x00001123,
        ERRINFO_SECURITYDATATOOSHORT21 = 0x00001124,
        ERRINFO_SECURITYDATATOOSHORT22 = 0x00001125,
        ERRINFO_SECURITYDATATOOSHORT23 = 0x00001126,
        ERRINFO_BADMONITORDATA = 0x00001129,
        ERRINFO_VCDECOMPRESSEDREASSEMBLEFAILED = 0x0000112A,
        ERRINFO_VCDATATOOLONG = 0x0000112B,
        ERRINFO_BAD_FRAME_ACK_DATA = 0x0000112C,
        ERRINFO_GRAPHICSMODENOTSUPPORTED = 0x0000112D,
        ERRINFO_GRAPHICSSUBSYSTEMRESETFAILED = 0x0000112E,
        ERRINFO_GRAPHICSSUBSYSTEMFAILED = 0x0000112F,
        ERRINFO_TIMEZONEKEYNAMELENGTHTOOSHORT = 0x00001130,
        ERRINFO_TIMEZONEKEYNAMELENGTHTOOLONG = 0x00001131,
        ERRINFO_DYNAMICDSTDISABLEDFIELDMISSING = 0x00001132,
        ERRINFO_VCDECODINGERROR = 0x00001133,
        ERRINFO_UPDATESESSIONKEYFAILED = 0x00001191,
        ERRINFO_DECRYPTFAILED = 0x00001192,
        ERRINFO_ENCRYPTFAILED = 0x00001193,
        ERRINFO_ENCPKGMISMATCH = 0x00001194,
        ERRINFO_DECRYPTFAILED2 = 0x00001195,
    };

    string errorMessage(uint32_t eno);

    /// @summary: PDU use in slow - path sending client inputs
    /// @see: http://msdn.microsoft.com/en-us/library/cc240583.aspx
    struct SlowPathInputEvent
    {
        uint32_t eventTime;
        uint16_t messageType;

		SlowPathInputEvent() : eventTime(0), messageType(0) {}
    };

    /// @summary: Synchronize keyboard
    /// @see: https://msdn.microsoft.com/en-us/library/cc240588.aspx
    struct SynchronizeEvent {
        uint16_t pad2Octets;
        uint32_t toggleFlags;

		SynchronizeEvent() : pad2Octets(0), toggleFlags(0) {}
    };

    /// @summary: Event use to communicate mouse position
    /// @see: http://msdn.microsoft.com/en-us/library/cc240586.aspx
    struct PointerEvent {
        uint16_t pointerFlags;
        uint16_t xPos;
        uint16_t yPos;

		PointerEvent() : pointerFlags(0), xPos(0), yPos(0) {}
    };

    /// @summary: Event use to communicate keyboard informations
    /// @see: http://msdn.microsoft.com/en-us/library/cc240584.aspx  
    struct ScancodeKeyEvent {
        uint16_t keyboardFlags;
        uint16_t keycode;
        uint16_t pad2Octets;

        ScancodeKeyEvent() : keyboardFlags(0), keycode(0), pad2Octets(0) {}
    };

    /// @summary: Event use to communicate keyboard informations
    /// @see: http://msdn.microsoft.com/en-us/library/cc240585.aspx
    struct UnicodeKeyEvent {
        uint16_t keyboardFlags;
        uint16_t unicode;
        uint16_t pad2Octets;

        UnicodeKeyEvent() : keyboardFlags(0), unicode(0), pad2Octets(0) {}
    };

    /// @summary: PDU share control header
    /// @see: http://msdn.microsoft.com/en-us/library/cc240576.aspx
    struct ShareControlHeader {
        uint16_t totalLength;
        uint16_t pduType;
        // for xp sp3 and deactiveallpdu PDUSource may not be present
        uint16_t PDUSource; // optional

		ShareControlHeader() : totalLength(0), pduType(0), PDUSource(0) {}
        void read(Buffer *s)
        {
			totalLength = s->readUInt16();
			pduType = s->readUInt16();
			if (s->length() >= sizeof(PDUSource))
				PDUSource = s->readUInt16();
        }
		uint16_t minSize()
		{
			return sizeof(totalLength) + sizeof(pduType);
		}
    };

    /// @summary: PDU share data header
    /// @see: http://msdn.microsoft.com/en-us/library/cc240577.aspx
    struct ShareDataHeader {
        uint32_t shareId;
        uint8_t pad1;
        uint8_t streamId;
        uint16_t uncompressedLength;
        uint8_t pduType2;
        uint8_t compressedType;
        uint16_t compressedLength;

		ShareDataHeader()
			: shareId(0), pad1(0), streamId(0), uncompressedLength(0)
			, pduType2(0), compressedType(0), compressedLength(0)
		{}
        void read(Buffer *s)
        {
			s->retrieve(&shareId, sizeof(ShareDataHeader));
        }
    };

    /// @see: http://msdn.microsoft.com/en-us/library/cc240485.aspx
    /// @summary: Main use for capabilities exchange server->client
    struct DemandActivePDU {
        uint32_t shareId;
        uint16_t lengthSourceDescriptor;
        uint16_t lengthCombinedCapabilities;
        string sourceDescriptor;
        uint16_t numberCapabilities;
        uint16_t pad2Octets;
        Buffer capabilitySets;
        uint32_t sessionId;

        DemandActivePDU(uint32_t shareId = 0) 
			: sourceDescriptor("rdpp"), lengthSourceDescriptor(4)
			, shareId(shareId), pad2Octets(0), sessionId(0)
			, numberCapabilities(0)
		{}

        void read(Buffer *s)
        {
            shareId = s->readUInt32();
            lengthSourceDescriptor = s->readUInt16();
            lengthCombinedCapabilities = s->readUInt16();
            sourceDescriptor = s->retrieveAsString(lengthSourceDescriptor);
            numberCapabilities = s->readUInt16();
            pad2Octets = s->readUInt16();

            const size_t setLength = lengthCombinedCapabilities - sizeof(numberCapabilities) - sizeof(pad2Octets);
            capabilitySets.append(s->data(), setLength);
            s->retrieve(setLength);
            sessionId = s->readUInt32();
        }
        void write(Buffer *s)
        {
            s->appendUInt32(shareId);
            s->appendUInt16(lengthSourceDescriptor);
            s->appendUInt16(lengthCombinedCapabilities);
            s->append(sourceDescriptor);
            s->appendUInt16(numberCapabilities);
            s->appendUInt16(pad2Octets);
            s->append(capabilitySets.data(), capabilitySets.length());
            s->appendUInt32(sessionId);
        }
    };

    /// @see: http://msdn.microsoft.com/en-us/library/cc240488.aspx
    /// @summary: Main use for capabilities confirm client->sever
    struct ConfirmActivePDU {
        uint32_t shareId;
        uint16_t originatorId;
        uint16_t lengthSourceDescriptor;
        uint16_t lengthCombinedCapabilities;
        string sourceDescriptor;
        uint16_t numberCapabilities;
        uint16_t pad2Octets;
        Buffer capabilitySets;

        ConfirmActivePDU(uint32_t shareId = 0)
			: shareId(shareId), originatorId(0x03EA), pad2Octets(0), sourceDescriptor("rdpp")
			, lengthCombinedCapabilities(0), numberCapabilities(0)
        {
            lengthSourceDescriptor = sourceDescriptor.length();
        }
        void read(Buffer *s)
        {
            shareId = s->readUInt32();
            originatorId = s->readUInt16();
            lengthSourceDescriptor = s->readUInt16();
            lengthCombinedCapabilities = s->readUInt16();
            sourceDescriptor = s->retrieveAsString(lengthSourceDescriptor);
            numberCapabilities = s->readUInt16();
            pad2Octets = s->readUInt16();

            const size_t setLength = lengthCombinedCapabilities - sizeof(numberCapabilities) - sizeof(pad2Octets);
            capabilitySets.append(s->data(), setLength);
            s->retrieve(setLength);
        }

        void write(Buffer *s)
        {
			assert(lengthSourceDescriptor == sourceDescriptor.length());
			assert(lengthCombinedCapabilities == (4 + capabilitySets.length()));

            s->appendUInt32(shareId);
            s->appendUInt16(originatorId);
            s->appendUInt16(lengthSourceDescriptor);
            s->appendUInt16(lengthCombinedCapabilities);
            s->append(sourceDescriptor);
            s->appendUInt16(numberCapabilities);
            s->appendUInt16(pad2Octets);
            s->append(capabilitySets.data(), capabilitySets.length());
        }
    };

    /// @summary: Use to signal already connected session
    /// @see: http://msdn.microsoft.com/en-us/library/cc240536.aspx
    struct DeactiveAllPDU {
        // in old version this packet is empty i don't know
        // and not specified
        uint32_t shareId;
        uint16_t lengthSourceDescriptor;
        string sourceDescriptor;

        DeactiveAllPDU() : shareId(0), sourceDescriptor("rdpp")
        {
            lengthSourceDescriptor = sourceDescriptor.length();
        }
        void write(Buffer *s)
        {
            s->appendUInt32(shareId);
            s->appendUInt16(lengthSourceDescriptor);
            s->append(sourceDescriptor);
        }
    };

    /// @see http://msdn.microsoft.com/en-us/library/cc240490.aspx
    struct SynchronizeDataPDU {
        uint16_t messageType;
        uint16_t targetUser;

        SynchronizeDataPDU(uint16_t target) : messageType(1), targetUser(target) {}
    };

    /// @see http://msdn.microsoft.com/en-us/library/cc240492.aspx
    struct ControlDataPDU {
        uint16_t action;
        uint16_t grantId;
        uint32_t controlId;

        ControlDataPDU(uint16_t action = 0) 
            : action(action), grantId(0), controlId(0) {}
    };

    /// @summary: Use to inform error in PDU layer
    /// @see: http://msdn.microsoft.com/en-us/library/cc240544.aspx
    struct ErrorInfoDataPDU
    {
        // use to collect error info PDU
        uint32_t errorInfo;
    };

    /// @summary: Use to indicate list of font.Deprecated packet
    /// client->server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240498.aspx
    struct FontListDataPDU
    {
        uint16_t numberFonts;
        uint16_t totalNumFonts;
        uint16_t listFlags;
        uint16_t entrySize;

        FontListDataPDU() 
            : numberFonts(0), totalNumFonts(0), listFlags(0x0003), entrySize(0x0032) {}
    };

    /// @summary: Use to indicate map of font.Deprecated packet(maybe the same as FontListDataPDU)
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240498.aspx
    struct FontMapDataPDU {
        uint16_t numberEntries;
        uint16_t totalNumEntries;
        uint16_t mapFlags;
        uint16_t entrySize;

        FontMapDataPDU()
            : numberEntries(0), totalNumEntries(0), mapFlags(0x0003), entrySize(0x0004) {}
    };

    /// @summary: Use to record persistent key in PersistentListPDU
    /// @see: http://msdn.microsoft.com/en-us/library/cc240496.aspx
    struct PersistentListEntry {
        uint32_t key1;
        uint32_t key2;
    };

    /// @summary: Use to indicate that bitmap cache was already
    /// Fill with some keys from previous session
    /// @see: http://msdn.microsoft.com/en-us/library/cc240495.aspx
    struct PersistentListPDU {
        struct {
            uint16_t numEntriesCache0;
            uint16_t numEntriesCache1;
            uint16_t numEntriesCache2;
            uint16_t numEntriesCache3;
            uint16_t numEntriesCache4;
            uint16_t totalEntriesCache0;
            uint16_t totalEntriesCache1;
            uint16_t totalEntriesCache2;
            uint16_t totalEntriesCache3;
            uint16_t totalEntriesCache4;
            uint8_t bitMask;
            uint8_t pad2;
            uint16_t pad3;
        } d1;
        std::vector<PersistentListEntry> entries;
    };

    /// @summary: PDU use to send client inputs in slow path mode
    /// @see: http://msdn.microsoft.com/en-us/library/cc746160.aspx
    struct ClientInputEventPDU {
        uint16_t numEvents;
        uint16_t pad2Octets;
        // std::vector<SlowPathInputEvent *> slowPathInputEvents;
        
        ClientInputEventPDU(uint16_t numEvents = 0) : numEvents(numEvents), pad2Octets(0) {}
    };

    /// @summary: PDU use to signal that the session will be closed
    /// client->server
    struct ShutdownRequestPDU {
        // nul
    };

    /// @summary: PDU use to signal which the session will be closed is connected
    /// server->client
    struct ShutdownDeniedPDU
    {
        // nul
    };

    /// @see: http://msdn.microsoft.com/en-us/library/cc240643.aspx
    struct InclusiveRectangle {
        uint16_t left;
        uint16_t top;
        uint16_t right;
        uint16_t bottom;
    };

    /// @see: http://msdn.microsoft.com/en-us/library/cc240648.aspx
    struct SupressOutputDataPDU {
        uint8_t allowDisplayUpdates;
        uint8_t pad3Octets[3];
        std::vector<InclusiveRectangle> desktopRect;
    };

    /// @see: http://msdn.microsoft.com/en-us/library/cc240646.aspx
    struct RefreshRectPDU {
        uint8_t numberOfAreas;
        uint8_t pad3Octets[3];
        std::vector<InclusiveRectangle> areasToRefresh;

        RefreshRectPDU()
        {
            memset(pad3Octets, 0, sizeof(pad3Octets));
        }
        
        void write(Buffer *s)
        {
            s->appendUInt8(numberOfAreas);
            s->appendUInt8(pad3Octets[0]);
            s->appendUInt8(pad3Octets[1]);
            s->appendUInt8(pad3Octets[2]);

            for (size_t i = 0; i < numberOfAreas; ++i)
                s->append(&(areasToRefresh[i]), sizeof(InclusiveRectangle));
        }
    };

    /// @summary: Update data PDU use by server to inform update image or palet
    /// for example
    /// @see: http://msdn.microsoft.com/en-us/library/cc240608.aspx
    struct UpdateDataPDU
    {
        uint16_t updateType;
    };

    /// @see: https://msdn.microsoft.com/en-us/library/cc240636.aspx
    struct SaveSessionInfoPDU {
        uint32_t infoType;
        // TODO parse info data
        string infoData;

        void read(Buffer *s, uint16_t readLen)
        {
            infoType = s->readUInt32();
            infoData = s->retrieveAsString(readLen - sizeof(infoType));
        }
    };

    /// @summary: Fast path update PDU packet
    /// @see: http://msdn.microsoft.com/en-us/library/cc240622.aspx
    struct FastPathUpdatePDU {
        uint8_t updateHeader;
        uint8_t compressionFlags;
        uint16_t size;

		FastPathUpdatePDU(uint8_t updateHeader = 0, 
			              uint8_t compressionFlags = 0,
			              uint16_t size = 0)
			: updateHeader(updateHeader)
			, compressionFlags(compressionFlags)
			, size(size)
		{}
		void read(Buffer *s)
        {
            updateHeader = s->readUInt8();
            if ((updateHeader >> 4) & FASTPATH_OUTPUT_COMPRESSION_USED)
                compressionFlags = s->readUInt8();
            size = s->readUInt16();
        }
		void prepend(Buffer *s)
		{
			s->prependUInt16(size);
			if ((updateHeader >> 4) & FASTPATH_OUTPUT_COMPRESSION_USED)
				s->prependUInt8(compressionFlags);
			s->prependUInt8(updateHeader);
		}

        uint8_t type() const
        {
            return updateHeader & 0xf;
        }

    };

    /// @summary: Compressed header of bitmap
    /// @see: http://msdn.microsoft.com/en-us/library/cc240644.aspx
    struct BitmapCompressedDataHeader
    {
        uint16_t cbCompFirstRowSize;
        // compressed data size
        uint16_t cbCompMainBodySize;
        uint16_t cbScanWidth;
        // uncompressed data size
        uint16_t cbUncompressedSize;

        BitmapCompressedDataHeader() 
            : cbCompFirstRowSize(0), cbCompMainBodySize(0), cbScanWidth(0), cbUncompressedSize(0)
        {}
    };

    /// @summary: Bitmap data here the screen capture
    /// @see: https://msdn.microsoft.com/en-us/library/cc240612.aspx
    struct BitmapData {
        struct {
            uint16_t destLeft;
            uint16_t destTop;
            uint16_t destRight;
            uint16_t destBottom;
            uint16_t width;
            uint16_t height;
            uint16_t bitsPerPixel;
        } d;
        uint16_t flags;
        uint16_t bitmapLength;
        BitmapCompressedDataHeader bitmapComprHdr;
        string bitmapDataStream;

        BitmapData() : flags(0) {}

        void read(Buffer *s)
        {
			s->retrieve(&d, sizeof(d));
            flags = s->readUInt16();
            bitmapLength = s->readUInt16();

            if (!(flags & BITMAP_COMPRESSION) || flags & BITMAP_NO_COMPRESSION_HDR) {
                bitmapDataStream = s->retrieveAsString(bitmapLength);
            } else {
                s->retrieve(&bitmapComprHdr, sizeof(bitmapComprHdr));
                bitmapDataStream = s->retrieveAsString(bitmapComprHdr.cbCompMainBodySize);
            }
        }
        void write(Buffer *s)
        {
            s->append(&d, sizeof(d));
            s->appendUInt16(flags);
            
            if (!(flags & BITMAP_COMPRESSION) || flags & BITMAP_NO_COMPRESSION_HDR) {
                bitmapLength = bitmapDataStream.length();
                s->appendUInt16(bitmapLength);
                s->append(bitmapDataStream);
            } else {
                bitmapLength = sizeof(bitmapComprHdr) + bitmapDataStream.length();
                s->appendUInt16(bitmapLength);
                s->append(&bitmapComprHdr, sizeof(bitmapComprHdr));
                s->append(bitmapDataStream);
            }
        }
    };
    typedef shared_ptr<BitmapData> BitmapDataPtr;

    /// @summary: PDU use to send raw bitmap compressed or not
    /// @see: http://msdn.microsoft.com/en-us/library/dd306368.aspx
    struct BitmapUpdateDataPDU
    {
        uint16_t numberRectangles;
        std::vector<BitmapDataPtr> rectangles;

        void read(Buffer *s)
        {
            numberRectangles = s->readUInt16();
            for (size_t i = 0; i < numberRectangles; ++i) {
                BitmapDataPtr bmp(new BitmapData);
                bmp->read(s);
                rectangles.push_back(bmp);
            }
        }
        void write(Buffer *s)
        {
            s->appendUInt16(numberRectangles);
            for (size_t i = 0; i < numberRectangles; ++i) {
                rectangles[i]->write(s);
            }
        }
    };

    /// @summary: PDU type use to communicate Accelerated order(GDI)
    /// @see: http://msdn.microsoft.com/en-us/library/cc241571.aspx
    /// @todo: not implemented yet but need it
    struct OrderUpdateDataPDU {
        uint16_t pad2OctetsA;
        uint16_t numberOrders;
        uint16_t pad2OctetsB;
        std::vector<PrimaryDrawingOrder> orderData;
    };

    /// @summary: Fast path version of bitmap update PDU
    /// @see: http://msdn.microsoft.com/en-us/library/dd306368.aspx
    struct FastPathBitmapUpdateDataPDU {
        uint16_t header;
        uint16_t numberRectangles;
        std::vector<BitmapDataPtr> rectangles;

		FastPathBitmapUpdateDataPDU()
			: header(FASTPATH_UPDATETYPE_BITMAP), numberRectangles(0) 
		{}
        void read(Buffer *s)
        {
            header = s->readUInt16();
			assert(FASTPATH_UPDATETYPE_BITMAP == header);

            numberRectangles = s->readUInt16();

            for (size_t i = 0; i < numberRectangles; ++i) {
                BitmapDataPtr bmp(new BitmapData);
                bmp->read(s);
                rectangles.push_back(bmp);
            }
        }
        void write(Buffer *s)
        {
			assert(header == FASTPATH_UPDATETYPE_BITMAP);
            assert(numberRectangles == rectangles.size());

            s->appendUInt16(header);
            s->appendUInt16(numberRectangles);
            for (size_t i = 0; i < numberRectangles; ++i) {
                rectangles[i]->write(s);
            }
        }
    };

#include <core/poppack.h>

} // namespace rdpp

#endif // _RDPP_RDP_PDU_DATA_H_
