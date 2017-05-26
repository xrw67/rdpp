/**
 * Basic Encoding Rules use in RDP.
 * ASN.1 standard
 */

#ifndef _RDPP_CORE_BER_H_
#define _RDPP_CORE_BER_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/log.h>

namespace rdpp {

    class BER
    {
    public:
        enum BerPc
        {
            BER_PC_MASK = 0x20,
            BER_PRIMITIVE = 0x00,
            BER_CONSTRUCT = 0x20,
        };

        enum Class
        {
            BER_CLASS_MASK = 0xC0,
            BER_CLASS_UNIV = 0x00,
            BER_CLASS_APPL = 0x40,
            BER_CLASS_CTXT = 0x80,
            BER_CLASS_PRIV = 0xC0,
        };

        enum Tag
        {
            BER_TAG_MASK = 0x1F,
            BER_TAG_BOOLEAN = 0x01,
            BER_TAG_INTEGER = 0x02,
            BER_TAG_BIT_STRING = 0x03,
            BER_TAG_OCTET_STRING = 0x04,
            BER_TAG_OBJECT_IDENFIER = 0x06,
            BER_TAG_ENUMERATED = 0x0A,
            BER_TAG_SEQUENCE = 0x10,
            BER_TAG_SEQUENCE_OF = 0x10,
        };

        /// @summary: Return BER_CONSTRUCT if true
        /// BER_PRIMITIVE if false
        /// @param pc: boolean
        /// @return: BerPc value
        static int berPC(bool pc)
        {
            if (pc)
                return BER_CONSTRUCT;
            else
                return BER_PRIMITIVE;
        }

        static int sizeofLength(int length)
        {
            if (length > 0xFF)
                return 3;
            if (length > 0x7F)
                return 2;
            return 1;
        }

        static bool readLength(Buffer *s, int &length)
        {
            if (s->length() < 1)
                return false;
            uint8_t byte = s->readUInt8();

            if (byte & 0x80) {
                byte &= ~(0x80);
                if (s->length() < byte)
                    return false;

                if (byte == 1)
                    length = s->readUInt8();
                else if (byte == 2)
                    length = s->readUInt16Be();
                else
                    return false;
            } else {
                length = byte;
            }
            return true;
        }

        /**
        * Write BER length.
        * @param s stream
        * @param length length
        */
        static int writeLength( Buffer *s, int length)
        {
            if (length > 0xFF) {
                s->appendUInt8((uint8_t)(0x80 ^ 2));
                s->appendUInt16Be(length);
                return 3;
            }
            if (length > 0x7F) {
                s->appendUInt8((uint8_t)(0x80 ^ 1));
                s->appendUInt8(length);
                return 2;
            }
            s->appendUInt8(length);
            return 1;
        }

        /**
        * Read BER Universal tag.
        * @param s stream
        * @param tag BER universally-defined tag
        * @return
        */
        static bool readUniversalTag(Buffer *s, uint8_t tag, bool pc)
        {
            if (s->length() < 1)
                return false;
            uint8_t byte = s->readUInt8();
            return byte == ((BER_CLASS_UNIV | berPC(pc)) | (BER_TAG_MASK & tag));
        }

        /**
        * Write BER Universal tag.
        * @param s stream
        * @param tag BER universally-defined tag
        * @param pc primitive (FALSE) or constructed (TRUE)
        */
        static int writeUniversalTag(Buffer *s, uint8_t tag, bool pc)
        {
            s->appendUInt8((BER_CLASS_UNIV | berPC(pc)) | (BER_TAG_MASK & tag));
            return 1;
        }

        /**
        * Read BER Application tag.
        * @param s stream
        * @param tag BER application-defined tag
        * @param length length
        */
        static bool readApplicationTag(Buffer *s, uint8_t tag, int &length)
        {
            uint8_t byte;

            if (tag > 30) {
                if (s->length() < 1)
                    return false;
                byte = s->readUInt8();

                if (byte != ((BER_CLASS_APPL | BER_CONSTRUCT) | BER_TAG_MASK))
                    return false;
                
                if (s->length() < 1)
                    return false;
                byte = s->readUInt8();

                if (byte != tag)
                    return false;

                return readLength(s, length);
            } else {
                if (s->length() < 1)
                    return false;
                byte = s->readUInt8();

                if (byte != ((BER_CLASS_APPL | BER_CONSTRUCT) | (BER_TAG_MASK & tag)))
                    return false;

                return readLength(s, length);
            }
            return true;
        }

        /**
        * Write BER Application tag.
        * @param s stream
        * @param tag BER application-defined tag
        * @param length length
        */
        static void writeApplicationTag(Buffer *s, uint8_t tag, int length)
        {
            if (tag > 30) {
                s->appendUInt8((BER_CLASS_APPL | BER_CONSTRUCT) | BER_TAG_MASK);
                s->appendUInt8(tag);
                writeLength(s, length);
            } else {
                s->appendUInt8((BER_CLASS_APPL | BER_CONSTRUCT) | (BER_TAG_MASK & tag));
                writeLength(s, length);
            }
        }

        static bool readContextualTag(Buffer *s, uint8_t tag, int &length, bool pc)
        {
            uint8_t byte;

            if (s->length() < 1)
                return false;
            byte = s->peekUInt8();

            if (byte != ((BER_CLASS_CTXT | berPC(pc)) | (BER_TAG_MASK & tag)))
                return false;

            s->retrieve(1);
            return readLength(s, length);
        }

        static int writeContextualTag(Buffer *s, uint8_t tag, int length, bool pc)
        {
            s->appendUInt8((BER_CLASS_CTXT | berPC(pc)) | (BER_TAG_MASK & tag));
            return 1 + writeLength(s, length);
        }

        static int sizeofContextualTag(int length)
        {
            return 1 + sizeofLength(length);
        }

        static bool readSequenceTag(Buffer *s, int &length)
        {
            uint8_t byte;

            if (s->length() < 1)
                return false;
            byte = s->readUInt8();

            if (byte != ((BER_CLASS_UNIV | BER_CONSTRUCT) | (BER_TAG_SEQUENCE_OF)))
                return false;

            return readLength(s, length);
        }

        /**
        * Write BER SEQUENCE tag.
        * @param s stream
        * @param length length
        */
        static int writeSequenceTag(Buffer *s, int length)
        {
            s->appendUInt8((BER_CLASS_UNIV | BER_CONSTRUCT) | (BER_TAG_MASK & BER_TAG_SEQUENCE));
            return 1 + writeLength(s, length);
        }

        static int sizeofSequence(int length)
        {
            return 1 + sizeofLength(length) + length;
        }

        static int sizeofSequenceTag(int length)
        {
            return 1 + sizeofLength(length);
        }

        /**
        * Read a BER BOOLEAN
        * @param s
        * @param value
        */
        static bool readBoolean(Buffer *s, bool &value)
        {
            int length;
            uint8_t v;

            if (!readUniversalTag(s, BER_TAG_BOOLEAN, false) || !readLength(s, length))
                return false;
            if (length != 1 || s->length() < 1)
                return false;

            v = s->readUInt8();
            value = ((v != 0) ? true : false);
            return true;
        }

        /**
        * Write a BER BOOLEAN
        * @param s
        * @param value
        */
        static void writeBoolean(Buffer *s, bool value)
        {
            writeUniversalTag(s, BER_TAG_BOOLEAN, false);
            writeLength(s, 1);
            s->appendUInt8(value ? 0xFF : 0);
        }

        static bool readInteger(Buffer *s, uint32_t &value)
        {
            int length;

            if (!readUniversalTag(s, BER_TAG_INTEGER, false) ||
                    !readLength(s, length) ||
                    ((int)s->length() < length))
                return false;

            if (length == 1) {
                value = s->readUInt8();
            } else if (length == 2) {
                value = s->readUInt16Be();
            } else if (length == 3) {
                uint8_t byte = s->readUInt8();
                value = s->readUInt16Be();
                value += (byte << 16);
            } else if (length == 4) {
                value = s->readUInt32Be();
            } else {
                return false; // Wrong integer size
            }
            return true;
        }

        /**
        * Write a BER INTEGER
        * @param s
        * @param value
        */
        static int writeInteger(Buffer *s, uint32_t value)
        {
            if (value < 0x80) {
                writeUniversalTag(s, BER_TAG_INTEGER, false);
                writeLength(s, 1);
                s->appendUInt8(value);
                return 3;
            } else if (value < 0x8000) {
                writeUniversalTag(s, BER_TAG_INTEGER, false);
                writeLength(s, 2);
                s->appendUInt16(value);
                return 4;
            } else if (value < 0x800000) {
                writeUniversalTag(s, BER_TAG_INTEGER, false);
                writeLength(s, 3);
                s->appendUInt8(value >> 16);
                s->appendUInt16Be(value & 0xffff);
                return 5;
            } else if (value < 0x80000000) {
                writeUniversalTag(s, BER_TAG_INTEGER, false);
                writeLength(s, 4);
                s->appendUInt32Be(value);
                return 6;
            } else {
                /* treat as signed integer i.e. NT/HRESULT error codes */
                writeUniversalTag(s, BER_TAG_INTEGER, false);
                writeLength(s, 4);
                s->appendUInt32Be(value);
                return 6;
            }
            return 0;
        }

        static int BER::sizeofInteger(uint32_t value)
        {
            if (value < 0x80)
                return 3;
            else if (value < 0x8000)
                return 4;
            else if (value < 0x800000)
                return 5;
            else if (value < 0x80000000)
                return 6;
            else // treat as signed integer i.e. NT/HRESULT error codes
                return 6;

            return 0;
        }

		static bool readIntegerLength(Buffer *s, int &length)
		{
			return readUniversalTag(s, BER_TAG_INTEGER, false) &&
				   readLength(s, length);
		}
		
        static bool readOctetString(Buffer *s, string &value)
        {
            int length;

            if (!readUniversalTag(s, BER_TAG_OCTET_STRING, false)) {
				RDPP_LOG("BER", ERROR) << "Unexpected BER tag";
				return false;
			}
            if (!readLength(s, length) || ((int)s->length() < length))
                return false;

            value = s->retrieveAsString(length);
            return true;
        }

		static bool readBitString(Buffer *s, int &length, uint8_t &padding)
		{
			if (!readUniversalTag(s, BER_TAG_BIT_STRING, false) || !readLength(s, length))
				return false;
			if (s->length() < 1)
				return false;
			padding = s->readUInt8();
			return true;
		}

        /**
        * Write a BER OCTET_STRING
        * @param s stream
        * @param oct_str octet string
        * @param length string length
        */
        static int writeOctetString(Buffer *s, const char *value, int length)
        {
            int size = 0;
            size += writeUniversalTag(s, BER_TAG_OCTET_STRING, false);
            size += writeLength(s, length);
            s->append(value, length);
            size += length;
            return size;
        }

        static bool readOctetStringTag(Buffer *s, int &length)
        {
            return readUniversalTag(s, BER_TAG_OCTET_STRING, false) && readLength(s, length);
        }

        static int writeOctetStringTag(Buffer *s, int length)
        {
            writeUniversalTag(s, BER_TAG_OCTET_STRING, false);
            writeLength(s, length);
            return 1 + sizeofLength(length);
        }

        static int sizeofOctetString(int length)
        {
            return 1 + sizeofLength(length) + length;
        }

        static bool readEnumerated(Buffer *s, uint8_t &enumerated, uint8_t count = 0xff)
        {
            int length;

            if (!readUniversalTag(s, BER_TAG_ENUMERATED, false) ||
                    !readLength(s, length))
                return false;

            if (length != 1 || s->length() < 1)
                return false;
            enumerated = s->readUInt8();

            if (enumerated + 1 > count)
                return false;
            return true;
        }


        static void writeEnumerated(Buffer *s, uint8_t enumerated, uint8_t count = 0)
        {
            writeUniversalTag(s, BER_TAG_ENUMERATED, false);
            writeLength(s, 1);
            s->appendUInt8(enumerated);
        }

        static int sizeofSequenceOctetString(int length)
        {
            return sizeofContextualTag(sizeofOctetString(length)) + sizeofOctetString(length);
        }

        static int writeSequenceOctetString(Buffer *s, uint8_t context, const char *value, int length)
        {
            return writeContextualTag(s, context, sizeofOctetString(length), true) + writeOctetString(s, value, length);
        }
    };

} // namespace rdpp

#endif // _RDPP_CORE_BER_H_

 