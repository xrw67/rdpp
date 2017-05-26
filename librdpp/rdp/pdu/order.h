/**
 * GDI order structure
 */
#ifndef _RDPP_RDP_PDU_ORDER_H_
#define _RDPP_RDP_PDU_ORDER_H_

#include <core/config.h>

namespace rdpp {

#include <core/pshpack1.h>

    /// @summary: Class order of drawing order
    /// @see: http://msdn.microsoft.com/en-us/library/cc241586.aspx
    enum ControlFlag {
        TS_STANDARD = 0x01,
        TS_SECONDARY = 0x02,
        TS_BOUNDS = 0x04,
        TS_TYPE_CHANGE = 0x08,
        TS_DELTA_COORDINATES = 0x10,
        TS_ZERO_BOUNDS_DELTAS = 0x20,
        TS_ZERO_FIELD_BYTE_BIT0 = 0x40,
        TS_ZERO_FIELD_BYTE_BIT1 = 0x80,
    };

    /// @summary: Primary order type
    /// @see: http://msdn.microsoft.com/en-us/library/cc241586.aspx
    enum OrderType {
        TS_ENC_DSTBLT_ORDER = 0x00,
        TS_ENC_PATBLT_ORDER = 0x01,
        TS_ENC_SCRBLT_ORDER = 0x02,
        TS_ENC_DRAWNINEGRID_ORDER = 0x07,
        TS_ENC_MULTI_DRAWNINEGRID_ORDER = 0x08,
        TS_ENC_LINETO_ORDER = 0x09,
        TS_ENC_OPAQUERECT_ORDER = 0x0A,
        TS_ENC_SAVEBITMAP_ORDER = 0x0B,
        TS_ENC_MEMBLT_ORDER = 0x0D,
        TS_ENC_MEM3BLT_ORDER = 0x0E,
        TS_ENC_MULTIDSTBLT_ORDER = 0x0F,
        TS_ENC_MULTIPATBLT_ORDER = 0x10,
        TS_ENC_MULTISCRBLT_ORDER = 0x11,
        TS_ENC_MULTIOPAQUERECT_ORDER = 0x12,
        TS_ENC_FAST_INDEX_ORDER = 0x13,
        TS_ENC_POLYGON_SC_ORDER = 0x14,
        TS_ENC_POLYGON_CB_ORDER = 0x15,
        TS_ENC_POLYLINE_ORDER = 0x16,
        TS_ENC_FAST_GLYPH_ORDER = 0x18,
        TS_ENC_ELLIPSE_SC_ORDER = 0x19,
        TS_ENC_ELLIPSE_CB_ORDER = 0x1A,
        TS_ENC_INDEX_ORDER = 0x1B,
    };

    /// @summary: used to describe a value in the range - 32768 to 32767
    /// @see: http://msdn.microsoft.com/en-us/library/cc241577.aspx
    struct CoordField
    {
        int8_t delta;
        int16_t coordinate;
    };

    /// @summary: GDI Primary drawing order
    /// @see: http://msdn.microsoft.com/en-us/library/cc241586.aspx
    struct PrimaryDrawingOrder
    {
        uint8_t controlFlags;
        uint8_t orderType;
    };

    /// @summary: The DstBlt Primary Drawing Order is used to paint
    /// a rectangle by using a destination - only raster operation.
    /// @see: http://msdn.microsoft.com/en-us/library/cc241587.aspx
    struct DstBltOrder
    {
        // only one field
        uint8_t fieldFlag;
        CoordField nLeftRect;
        CoordField nTopRect;
        CoordField nWidth;
        CoordField nHeight;
        CoordField bRop;
    };

#include <core/poppack.h>

} // namespace rdpp

#endif // _RDPP_RDP_PDU_ORDER_H_
