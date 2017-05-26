/**
 * Definition of structure use for capabilities nego
 * Use in PDU layer
 */
#ifndef _RDPP_RDP_PDU_CAPS_H_
#define _RDPP_RDP_PDU_CAPS_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/log.h>
#include <vector>

namespace rdpp {

#include <core/pshpack1.h>

    /// @summary: Different type of capabilities
    /// @see: http://msdn.microsoft.com/en-us/library/cc240486.aspx
    enum CapsType {
        CAPSTYPE_GENERAL = 0x0001,
        CAPSTYPE_BITMAP = 0x0002,
        CAPSTYPE_ORDER = 0x0003,
        CAPSTYPE_BITMAPCACHE = 0x0004,
        CAPSTYPE_CONTROL = 0x0005,
        CAPSTYPE_ACTIVATION = 0x0007,
        CAPSTYPE_POINTER = 0x0008,
        CAPSTYPE_SHARE = 0x0009,
        CAPSTYPE_COLORCACHE = 0x000A,
        CAPSTYPE_SOUND = 0x000C,
        CAPSTYPE_INPUT = 0x000D,
        CAPSTYPE_FONT = 0x000E,
        CAPSTYPE_BRUSH = 0x000F,
        CAPSTYPE_GLYPHCACHE = 0x0010,
        CAPSTYPE_OFFSCREENCACHE = 0x0011,
        CAPSTYPE_BITMAPCACHE_HOSTSUPPORT = 0x0012,
        CAPSTYPE_BITMAPCACHE_REV2 = 0x0013,
        CAPSTYPE_VIRTUALCHANNEL = 0x0014,
        CAPSTYPE_DRAWNINEGRIDCACHE = 0x0015,
        CAPSTYPE_DRAWGDIPLUS = 0x0016,
        CAPSTYPE_RAIL = 0x0017,
        CAPSTYPE_WINDOW = 0x0018,
        CAPSETTYPE_COMPDESK = 0x0019,
        CAPSETTYPE_MULTIFRAGMENTUPDATE = 0x001A,
        CAPSETTYPE_LARGE_POINTER = 0x001B,
        CAPSETTYPE_SURFACE_COMMANDS = 0x001C,
        CAPSETTYPE_BITMAP_CODECS = 0x001D,
        CAPSSETTYPE_FRAME_ACKNOWLEDGE = 0x001E,
    };

    /// @summary: Use in general capability
    /// @see: http://msdn.microsoft.com/en-us/library/cc240549.aspx
    enum MajorType {
        OSMAJORTYPE_UNSPECIFIED = 0x0000,
        OSMAJORTYPE_WINDOWS = 0x0001,
        OSMAJORTYPE_OS2 = 0x0002,
        OSMAJORTYPE_MACINTOSH = 0x0003,
        OSMAJORTYPE_UNIX = 0x0004,
        OSMAJORTYPE_IOS = 0x0005,
        OSMAJORTYPE_OSX = 0x0006,
        OSMAJORTYPE_ANDROID = 0x0007,
    };

    /// @summary: Use in general capability
    /// @see: http://msdn.microsoft.com/en-us/library/cc240549.aspx
    enum MinorType {
        OSMINORTYPE_UNSPECIFIED = 0x0000,
        OSMINORTYPE_WINDOWS_31X = 0x0001,
        OSMINORTYPE_WINDOWS_95 = 0x0002,
        OSMINORTYPE_WINDOWS_NT = 0x0003,
        OSMINORTYPE_OS2_V21 = 0x0004,
        OSMINORTYPE_POWER_PC = 0x0005,
        OSMINORTYPE_MACINTOSH = 0x0006,
        OSMINORTYPE_NATIVE_XSERVER = 0x0007,
        OSMINORTYPE_PSEUDO_XSERVER = 0x0008,
        OSMINORTYPE_WINDOWS_RT = 0x0009,
    };

    /// @summary: Use in general capability
    /// @see: http://msdn.microsoft.com/en-us/library/cc240549.aspx
    enum GeneralExtraFlag {
        FASTPATH_OUTPUT_SUPPORTED = 0x0001,
        NO_BITMAP_COMPRESSION_HDR = 0x0400,
        LONG_CREDENTIALS_SUPPORTED = 0x0004,
        AUTORECONNECT_SUPPORTED = 0x0008,
        ENC_SALTED_CHECKSUM = 0x0010,
    };

    enum Boolean {
        BOOLEAN_FALSE = 0x00,
        BOOLEAN_TRUE = 0x01,
    };

    /// @summary: Use in order capability
    /// @see: http://msdn.microsoft.com/en-us/library/cc240556.aspx
    enum OrderFlag {
        NEGOTIATEORDERSUPPORT = 0x0002,
        ZEROBOUNDSDELTASSUPPORT = 0x0008,
        COLORINDEXSUPPORT = 0x0020,
        SOLIDPATTERNBRUSHONLY = 0x0040,
        ORDERFLAGS_EXTRA_FLAGS = 0x0080,
    };

    /// @summary: Drawing orders supported
    /// Use in order capability
    /// @see: http://msdn.microsoft.com/en-us/library/cc240556.aspx
    enum Order {
        TS_NEG_DSTBLT_INDEX = 0x00,
        TS_NEG_PATBLT_INDEX = 0x01,
        TS_NEG_SCRBLT_INDEX = 0x02,
        TS_NEG_MEMBLT_INDEX = 0x03,
        TS_NEG_MEM3BLT_INDEX = 0x04,
        TS_NEG_DRAWNINEGRID_INDEX = 0x07,
        TS_NEG_LINETO_INDEX = 0x08,
        TS_NEG_MULTI_DRAWNINEGRID_INDEX = 0x09,
        TS_NEG_SAVEBITMAP_INDEX = 0x0B,
        TS_NEG_MULTIDSTBLT_INDEX = 0x0F,
        TS_NEG_MULTIPATBLT_INDEX = 0x10,
        TS_NEG_MULTISCRBLT_INDEX = 0x11,
        TS_NEG_MULTIOPAQUERECT_INDEX = 0x12,
        TS_NEG_FAST_INDEX_INDEX = 0x13,
        TS_NEG_POLYGON_SC_INDEX = 0x14,
        TS_NEG_POLYGON_CB_INDEX = 0x15,
        TS_NEG_POLYLINE_INDEX = 0x16,
        TS_NEG_FAST_GLYPH_INDEX = 0x18,
        TS_NEG_ELLIPSE_SC_INDEX = 0x19,
        TS_NEG_ELLIPSE_CB_INDEX = 0x1A,
        TS_NEG_INDEX_INDEX = 0x1B,
    };

    /// @summary: Extension orders
    /// Use in order capability
    enum OrderEx {
        ORDERFLAGS_EX_CACHE_BITMAP_REV3_SUPPORT = 0x0002,
        ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT = 0x0004,
    };

    /// @summary: Input flag use in input capability
    /// @see:  http://msdn.microsoft.com/en-us/library/cc240563.aspx
    enum InputFlags {
        INPUT_FLAG_SCANCODES = 0x0001,
        INPUT_FLAG_MOUSEX = 0x0004,
        INPUT_FLAG_FASTPATH_INPUT = 0x0008,
        INPUT_FLAG_UNICODE = 0x0010,
        INPUT_FLAG_FASTPATH_INPUT2 = 0x0020,
        INPUT_FLAG_UNUSED1 = 0x0040,
        INPUT_FLAG_UNUSED2 = 0x0080,
        TS_INPUT_FLAG_MOUSE_HWHEEL = 0x0100,
    };

    /// @summary: Brush support of client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240564.aspx
    enum BrushSupport {
        BRUSH_DEFAULT = 0x00000000,
        BRUSH_COLOR_8x8 = 0x00000001,
        BRUSH_COLOR_FULL = 0x00000002,
    };

    /// @summary: Use by glyph order
    /// @see: http://msdn.microsoft.com/en-us/library/cc240565.aspx
    enum GlyphSupport {
        GLYPH_SUPPORT_NONE = 0x0000,
        GLYPH_SUPPORT_PARTIAL = 0x0001,
        GLYPH_SUPPORT_FULL = 0x0002,
        GLYPH_SUPPORT_ENCODE = 0x0003,
    };

    /// @summary: Use to determine offscreen cache level supported
    /// @see: http://msdn.microsoft.com/en-us/library/cc240550.aspx
    enum OffscreenSupportLevel {
        OFFSCREEN_SUPPORT_LEVEL_FALSE = 0x00000000,
        OFFSCREEN_SUPPORT_LEVEL_TRUE = 0x00000001,
    };

    /// @summary: Use to determine virtual channel compression
    /// @see: http://msdn.microsoft.com/en-us/library/cc240551.aspx
    enum VirtualChannelCompressionFlag {
        VCCAPS_NO_COMPR = 0x00000000,
        VCCAPS_COMPR_SC = 0x00000001,
        VCCAPS_COMPR_CS_8K = 0x00000002,
    };

    /// @summary: Use in sound capability to inform it
    /// @see: http://msdn.microsoft.com/en-us/library/cc240552.aspx
    enum SoundFlag {
        SOUND_FLAG_NONE = 0x0000,
        SOUND_BEEPS_FLAG = 0x0001,
    };

    /// @summary: Use in capability cache exchange
    /// @see: http://msdn.microsoft.com/en-us/library/cc240566.aspx
    struct CacheEntry {
        uint16_t cacheEntries;
        uint16_t cacheMaximumCellSize;
    };

    /// @summary: A capability
    /// @see: http://msdn.microsoft.com/en-us/library/cc240486.aspx
    struct Capability {
        uint16_t capabilitySetType;
        uint16_t lengthCapability;

		Capability() 
		{}

		Capability(uint16_t type, uint16_t length)
			: capabilitySetType(type), lengthCapability(length)
		{}

		void setType(uint16_t type, uint16_t length)
		{
			capabilitySetType = type;
			lengthCapability = length;
		}
    };
    typedef shared_ptr<Capability> CapabilityPtr;

    /// @summary: General capability(protocol version and compression mode)
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240549.aspx
    struct GeneralCapability : public Capability {
        uint16_t osMajorType;
        uint16_t osMinorType;
        uint16_t protocolVersion; // const
        uint16_t pad2octetsA;
        uint16_t generalCompressionTypes; // const
        uint16_t extraFlags;
        uint16_t updateCapabilityFlag; // const 
        uint16_t remoteUnshareFlag; // const
        uint16_t generalCompressionLevel; // const
        uint8_t refreshRectSupport;
        uint8_t suppressOutputSupport;

		GeneralCapability()
		{
			memset(this, 0, sizeof(GeneralCapability));
			setType(CAPSTYPE_GENERAL, sizeof(GeneralCapability));
			protocolVersion = 0x0200;
		}
    };

    /// @summary: Bitmap format Capability
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240554.aspx
    struct BitmapCapability : public Capability {
        uint16_t preferredBitsPerPixel;
        uint16_t receive1BitPerPixel;
        uint16_t receive4BitsPerPixel;
        uint16_t receive8BitsPerPixel;
        uint16_t desktopWidth;
        uint16_t desktopHeight;
        uint16_t pad2octets;
        uint16_t desktopResizeFlag;
        uint16_t bitmapCompressionFlag; // const 
        uint8_t highColorFlags;
        uint8_t drawingFlags;
        uint16_t multipleRectangleSupport; // const
        uint16_t pad2octetsB;

		BitmapCapability()
		{
			memset(this, 0, sizeof(BitmapCapability));
			setType(CAPSTYPE_BITMAP, sizeof(BitmapCapability));
			receive1BitPerPixel = 0x0001;
			receive4BitsPerPixel = 0x0001;
			receive8BitsPerPixel = 0x0001;
			bitmapCompressionFlag = 0x0001;
			multipleRectangleSupport = 0x0001;
		}
    };

    /// @summary: Order capability list all drawing order supported
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240556.aspx
    struct OrderCapability : public Capability {
        char terminalDescriptor[16];
        uint32_t pad4octetsA;
        uint16_t desktopSaveXGranularity;
        uint16_t desktopSaveYGranularity;
        uint16_t pad2octetsA;
        uint16_t maximumOrderLevel;
        uint16_t numberFonts;
        uint16_t orderFlags;
        uint8_t orderSupport[32];
        uint16_t textFlags;
        uint16_t orderSupportExFlags;
        uint32_t pad4octetsB;
        uint32_t desktopSaveSize;
        uint16_t pad2octetsC;
        uint16_t pad2octetsD;
        uint16_t textANSICodePage;
        uint16_t pad2octetsE;

		OrderCapability()
		{
			memset(this, 0, sizeof(OrderCapability));
			setType(CAPSTYPE_ORDER, sizeof(OrderCapability));
			desktopSaveXGranularity = 1;
			desktopSaveYGranularity = 20;
			maximumOrderLevel = 1;
			orderFlags = NEGOTIATEORDERSUPPORT;
			desktopSaveSize = 480 * 480;
		}
    };

    /// @summary: Order use to cache bitmap very useful
    /// client->server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240559.aspx
    struct BitmapCacheCapability : public Capability {
        uint32_t pad1;
        uint32_t pad2;
        uint32_t pad3;
        uint32_t pad4;
        uint32_t pad5;
        uint32_t pad6;
        uint16_t cache0Entries;
        uint16_t cache0MaximumCellSize;
        uint16_t cache1Entries;
        uint16_t cache1MaximumCellSize;
        uint16_t cache2Entries;
        uint16_t cache2MaximumCellSize;

		BitmapCacheCapability()
		{
			memset(this, 0, sizeof(BitmapCacheCapability));
			setType(CAPSTYPE_BITMAPCACHE, sizeof(BitmapCacheCapability));
		}
    };

    /// @summary: Use to indicate pointer handle of client
    /// Paint by server or per client
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240562.aspx
    struct PointerCapability_Client : public Capability {
        uint16_t colorPointerFlag;
        uint16_t colorPointerCacheSize;

		PointerCapability_Client()
			: Capability(CAPSTYPE_POINTER, sizeof(PointerCapability_Client))
			, colorPointerFlag(BOOLEAN_TRUE), colorPointerCacheSize(20)
		{}
    };
	
	struct PointerCapability_Server : public Capability {
        uint16_t colorPointerFlag;
        uint16_t colorPointerCacheSize;
        // old version of rdp doesn't support ...
        uint16_t pointerCacheSize; // if isServer

		PointerCapability_Server(bool isServer = false)
			: Capability(CAPSTYPE_POINTER, sizeof(PointerCapability_Server))
			, colorPointerFlag(BOOLEAN_TRUE), colorPointerCacheSize(20)
			, pointerCacheSize(0)
		{}
    };

    /// @summary: Use to indicate input capabilities
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240563.aspx
    struct InputCapability : public Capability {
        uint16_t inputFlags;
        uint16_t pad2octetsA;
        // same value as gcc.ClientCoreSettings.kbdLayout
        uint32_t keyboardLayout;
        // same value as gcc.ClientCoreSettings.keyboardType
        uint32_t keyboardType;
        // same value as gcc.ClientCoreSettings.keyboardSubType
        uint32_t keyboardSubType;
        // same value as gcc.ClientCoreSettings.keyboardFnKeys
        uint32_t keyboardFunctionKey;
        // same value as gcc.ClientCoreSettingrrs.imeFileName
        char imeFileName[64];

		InputCapability()
		{
			memset(this, 0, sizeof(InputCapability));
			setType(CAPSTYPE_INPUT, sizeof(InputCapability));
		}
    };

    /// @summary: Use to indicate brush capability
    /// client->server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240564.aspx
    struct BrushCapability : public Capability {
        uint32_t brushSupportLevel;

		BrushCapability() 
			: Capability(CAPSTYPE_BRUSH, sizeof(BrushCapability))
			, brushSupportLevel(BRUSH_DEFAULT)
		{}
    };

    /// @summary: Use in font order
    /// client->server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240565.aspx
    struct GlyphCapability : public Capability {
        CacheEntry glyphCache[10];
        uint32_t fragCache;
        // all fonts are sent with bitmap format(very expensive)
        uint16_t glyphSupportLevel;
        uint16_t pad2octets;

		GlyphCapability()
		{
			memset(this, 0, sizeof(GlyphCapability));
			setType(CAPSTYPE_GLYPHCACHE, sizeof(GlyphCapability));
			glyphSupportLevel = GLYPH_SUPPORT_NONE;
		}
    };

    /// @summary: use to cached bitmap in offscreen area
    /// client->server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240550.aspx
    struct OffscreenBitmapCacheCapability : public Capability {
        uint32_t offscreenSupportLevel;
        uint16_t offscreenCacheSize;
        uint16_t offscreenCacheEntries;

		OffscreenBitmapCacheCapability() 
			: Capability(CAPSTYPE_OFFSCREENCACHE, sizeof(OffscreenBitmapCacheCapability))
			, offscreenSupportLevel(OFFSCREEN_SUPPORT_LEVEL_FALSE)
			, offscreenCacheSize(0), offscreenCacheEntries(0)
		{}
    };

    /// @summary: use to determine virtual channel compression
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240551.aspx
    struct VirtualChannelCapability : public Capability {
        uint32_t flags;
        uint32_t VCChunkSize; // optional

		VirtualChannelCapability() 
			: Capability(CAPSTYPE_VIRTUALCHANNEL, sizeof(VirtualChannelCapability))
			, flags(VCCAPS_NO_COMPR), VCChunkSize(0)
		{}
    };

    /// @summary: Use to exchange sound capability
    /// client->server
    /// @see: http://msdn.microsoft.com/en-us/library/cc240552.aspx
    struct SoundCapability : public Capability {
        uint16_t soundFlags;
        uint16_t pad2octetsA;

		SoundCapability()
			: Capability(CAPSTYPE_SOUND, sizeof(SoundCapability))
			, soundFlags(SOUND_FLAG_NONE), pad2octetsA(0)
		{}
    };

    /// @summary: client->server but server ignore contents!Thanks krosoft for brandwidth
    /// @see: http://msdn.microsoft.com/en-us/library/cc240568.aspx
    struct ControlCapability : public Capability {
        uint16_t controlFlags;
        uint16_t remoteDetachFlag;
        uint16_t controlInterest;
        uint16_t detachInterest;

		ControlCapability()
			: Capability(CAPSTYPE_CONTROL, sizeof(ControlCapability))
			, controlFlags(0), remoteDetachFlag(0)
			, controlInterest(0x0002), detachInterest(0x0002)
		{}
    };

    /// @summary: client->server but server ignore contents!Thanks krosoft for brandwidth
    /// @see: http://msdn.microsoft.com/en-us/library/cc240569.aspx
    struct WindowActivationCapability : public Capability {
        uint16_t helpKeyFlag;
        uint16_t helpKeyIndexFlag;
        uint16_t helpExtendedKeyFlag;
        uint16_t windowManagerKeyFlag;

		WindowActivationCapability()
		{
			memset(this, 0, sizeof(WindowActivationCapability));
			setType(CAPSTYPE_ACTIVATION, sizeof(WindowActivationCapability));
		}
    };

    /// @summary: Use to indicate font support
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240571.aspx
    struct FontCapability : public Capability {
        uint16_t fontSupportFlags;
        uint16_t pad2octets;

		FontCapability()
			: Capability(CAPSTYPE_FONT, sizeof(FontCapability))
			, fontSupportFlags(0x0001), pad2octets(0)
		{}
    };

    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc241564.aspx
    struct ColorCacheCapability : public Capability {
        uint16_t colorTableCacheSize;
        uint16_t pad2octets;

		ColorCacheCapability()
			: Capability(CAPSTYPE_COLORCACHE, sizeof(ColorCacheCapability))
			, colorTableCacheSize(0x0006), pad2octets(0)
		{}
    };

    /// @summary: Use to advertise channel id of server
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240570.aspx
    struct ShareCapability : public Capability {
        uint16_t nodeId;
        uint16_t pad2octets;

		ShareCapability()
			: Capability(CAPSTYPE_SHARE, sizeof(ShareCapability))
			, nodeId(0), pad2octets(0)
		{}
    };

    /// @summary: Use to advertise fast path max buffer to use
    /// client->server
    /// server->client
    /// @see: http://msdn.microsoft.com/en-us/library/cc240649.aspx
    struct MultiFragmentUpdate : public Capability {
        uint32_t MaxRequestSize;

		MultiFragmentUpdate()
			: Capability(CAPSETTYPE_MULTIFRAGMENTUPDATE, sizeof(MultiFragmentUpdate))
			, MaxRequestSize(0)
		{}
    };

    struct ServerCapabilitySets {
        GeneralCapability general;
        BitmapCapability bitmap;
        OrderCapability order;
		VirtualChannelCapability virtualChannel;
        PointerCapability_Server pointer;
		ShareCapability share;
		ColorCacheCapability colorCache;
        InputCapability input;
        FontCapability font;

		void read(const string &capData)
		{
		    Capability hdr;
			memcpy(&hdr, capData.c_str(), sizeof(hdr));

			switch (hdr.capabilitySetType) {
			case CAPSTYPE_GENERAL:
				memcpy(&general, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_BITMAP:
				memcpy(&bitmap, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_ORDER:
				memcpy(&order, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_POINTER:
				memcpy(&pointer, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_INPUT:
				memcpy(&input, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_VIRTUALCHANNEL:
				memcpy(&virtualChannel, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_FONT:
				memcpy(&font, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_COLORCACHE:
				memcpy(&colorCache, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_SHARE:
				memcpy(&share, capData.c_str(), hdr.lengthCapability);
				break;
			default:
				RDPP_LOG("CAPS", DEBUG) << "Unknown Server Capability type: " << (void *)hdr.capabilitySetType << ", length: " << hdr.lengthCapability;
			}
		}
    };

    struct ClientCapabilitySets {
        GeneralCapability general;
        BitmapCapability bitmap;
        OrderCapability order;
        BitmapCacheCapability bitmapCache;
        PointerCapability_Client pointer;
		SoundCapability sound;
        InputCapability input;
		BrushCapability brush;
        GlyphCapability glyph;
        OffscreenBitmapCacheCapability offscreenBitmapCache;
        VirtualChannelCapability virtualChannel;
        MultiFragmentUpdate multiFragmentUpdate;

		void read(const string &capData)
		{
		    Capability hdr;
			memcpy(&hdr, capData.c_str(), sizeof(hdr));

			switch (hdr.capabilitySetType) {
			case CAPSTYPE_GENERAL:
				memcpy(&general, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_BITMAP:
				memcpy(&bitmap, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_ORDER:
				memcpy(&order, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_BITMAPCACHE:
				memcpy(&bitmapCache, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_POINTER:
				memcpy(&pointer, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_INPUT:
				memcpy(&input, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_BRUSH:
				memcpy(&brush, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_GLYPHCACHE:
				memcpy(&glyph, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_OFFSCREENCACHE:
				memcpy(&offscreenBitmapCache, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_VIRTUALCHANNEL:
				memcpy(&virtualChannel, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSTYPE_SOUND:
				memcpy(&sound, capData.c_str(), hdr.lengthCapability);
				break;
			case CAPSETTYPE_MULTIFRAGMENTUPDATE:
				memcpy(&multiFragmentUpdate, capData.c_str(), hdr.lengthCapability);
				break;
			default:
				RDPP_LOG("CAPS", DEBUG) << "Unknown Server Capability type: " << (void *)hdr.capabilitySetType << ", length: " << hdr.lengthCapability;
			}
		}
    };

#include <core/poppack.h>

} // namespace rdpp

#endif // _RDPP_RDP_PDU_CAPS_H_
