/**
 * ASN.1 Packed Encoding Rules(PER)
 */

#ifndef _RDPP_CORE_PER_H_
#define _RDPP_CORE_PER_H_

#include <core/config.h>
#include <core/buffer.h>

namespace rdpp {

    class PER
    {
    public:
        /**
        * Read PER length.
        * @param s stream
        * @param length length
        * @return
        */
        static bool readLength(Buffer *s, uint16_t &length)
        {
            uint8_t byte;

            if (s->length() < 1)
                return false;
            byte = s->readUInt8();

            if (byte & 0x80) {
                if (s->length() < 1)
                    return false;

                byte &= ~(0x80);
                length = (byte << 8);
                byte = s->readUInt8();
                length += byte;
            } else {
                length = byte;
            }
            return true;
        }

        /**
        * Write PER length.
        * @param s stream
        * @param length length
        */
        static void writeLength(Buffer *s, uint32_t length)
        {
            if (length > 0x7f)
                s->appendUInt16Be(length | 0x8000);
            else
                s->appendUInt8(length);
        }

        /**
        * Read PER choice.
        * @param s stream
        * @param choice choice
        * @return
        */
        static bool readChoice(Buffer *s, uint8_t &choice)
        {
            if (s->length() < 1)
                return false;
            choice = s->readUInt8();
            return true;
        }

        /**
        * Write PER CHOICE.
        * @param s stream
        * @param choice index of chosen field
        */
        static void writeChoice(Buffer *s, uint8_t choice)
        {
            s->appendUInt8(choice);
        }

        /**
        * Read PER selection.
        * @param s stream
        * @param selection selection
        * @return
        */
        static bool readSelection(Buffer *s, uint8_t &selection)
        {
            if (s->length() < 1)
                return false;
            selection = s->readUInt8();
            return true;
        }

        /**
        * Write PER selection for OPTIONAL fields.
        * @param s stream
        * @param selection bit map of selected fields
        */
        static void writeSelection(Buffer *s, uint8_t selection)
        {
            s->appendUInt8(selection);
        }

        /**
        * Read PER number of sets.
        * @param s stream
        * @param number number of sets
        * @return
        */
        static bool readNumberOfSet(Buffer *s, uint8_t &number)
        {
            if (s->length() < 1)
                return false;
            number = s->readUInt8();
            return true;
        }

        /**
        * Write PER number of sets for SET OF.
        * @param s stream
        * @param number number of sets
        */
        static void writeNumberOfSet(Buffer *s, uint8_t number)
        {
            s->appendUInt8(number);
        }

        /**
        * Read PER ENUMERATED.
        * @param s stream
        * @param enumerated enumerated
        * @param count enumeration count
        * @return
        */
        static bool readEnumerates(Buffer *s, uint8_t &enumerated, uint8_t count = 0xff)
        {
            if (s->length() < 1)
                return false;
            enumerated = s->readUInt8();

            /* check that enumerated value falls within expected range */
            if (enumerated + 1 > count)
                return false;
            return true;
        }

        /**
        * Write PER ENUMERATED.
        * @param s stream
        * @param enumerated enumerated
        * @param count enumeration count
        * @return
        */
        static void writeEnumerates(Buffer *s, uint8_t enumerated, uint8_t count = 0)
        {
            s->appendUInt8(enumerated);
        }

        /**
        * Read PER INTEGER.
        * @param s stream
        * @param integer integer
        * @return
        */
        static bool readInteger(Buffer *s, uint32_t &integer)
        {
            uint16_t length;

            if (!readLength(s, length))
                return false;
            if (s->length() < length)
                return false;

            if (length == 0)
                integer = 0;
            else if (length == 1)
                integer = s->readUInt8();
            else if (length == 2)
                integer = s->readUInt16Be();
            else
                return false;

            return true;
        }

        /**
        * Write PER INTEGER.
        * @param s stream
        * @param integer integer
        */
        static void writeInteger(Buffer *s, uint32_t integer)
        {
            if (integer <= 0xFF) {
                writeLength(s, 1);
                s->appendUInt8(integer);
            } else if (integer <= 0xFFFF) {
                writeLength(s, 2);
                s->appendUInt16Be(integer);
            } else if (integer <= 0xFFFFFFFF) {
                writeLength(s, 4);
                s->appendUInt32Be(integer);
            }
        }

        /**
        * Read PER INTEGER (UINT16).
        * @param s stream
        * @param integer integer
        * @param min minimum value
        * @return
        */
        static bool readInteger16(Buffer *s, uint16_t &integer, uint16_t min = 0)
        {
            if (s->length() < 2)
                return false;
            integer = s->readUInt16Be();
            if (integer + min > 0xffff)
                return false;
            integer += min;
            return true;
        }

        /**
        * Write PER INTEGER (UINT16).
        * @param s stream
        * @param integer integer
        * @param min minimum value
        */
        static void writeInteger16(Buffer *s, uint16_t integer, uint16_t min = 0)
        {
            s->appendUInt16Be(integer - min);
        }

        /**
        * Read PER OBJECT_IDENTIFIER (OID).
        * @param s stream
        * @param oid object identifier (OID), must be a tuple of 6 elements
        * @return
        */
        static bool readObjectIdentifier(Buffer *s, const uint8_t oid[6])
        {
            uint8_t t12;
            uint16_t length;
            uint8_t a_oid[6];

            if (!readLength(s, length))
                return false;
            if (length != 5)
                return false;
            if (s->length() < length)
                return false;

            t12 = s->readUInt8(); /* first two tuples */
            a_oid[0] = (t12 >> 4);
            a_oid[1] = (t12 & 0x0F);

            a_oid[2] = s->readUInt8(); /* tuple 3 */
            a_oid[3] = s->readUInt8(); /* tuple 4 */
            a_oid[4] = s->readUInt8(); /* tuple 5 */
            a_oid[5] = s->readUInt8(); /* tuple 6 */

            if ((a_oid[0] == oid[0]) && (a_oid[1] == oid[1]) &&
                    (a_oid[2] == oid[2]) && (a_oid[3] == oid[3]) &&
                    (a_oid[4] == oid[4]) && (a_oid[5] == oid[5]))
                return true;
            else
                return false;
        }

        /**
        * Write PER OBJECT_IDENTIFIER (OID)
        * @param s stream
        * @param oid object identifier (oid)
        */
        static void writeObjectIdentifier(Buffer *s, const uint8_t oid[6])
        {
            uint8_t t12 = (oid[0] << 4) & (oid[1] & 0x0F);
            s->appendUInt8(5); /* length */
            s->appendUInt8(t12); /* first two tuples */
            s->appendUInt8(oid[2]); /* tuple 3 */
            s->appendUInt8(oid[3]); /* tuple 4 */
            s->appendUInt8(oid[4]); /* tuple 5 */
            s->appendUInt8(oid[5]); /* tuple 6 */
        }

        /**
        * Read PER NumericString.
        * @param s stream
        * @param num_str numeric string
        * @param length string length
        * @param min minimum string length
        */
        static bool readNumericString(Buffer *s, int min)
        {
            int length;
            uint16_t mlength;

            if (!readLength(s, mlength))
                return false;

            length = (mlength + min + 1) / 2;
            if (((int)s->length()) < length)
                return false;

            s->retrieve(length);
            return true;
        }

        /**
        * Write PER NumericString.
        * @param s stream
        * @param num_str numeric string
        * @param length string length
        * @param min minimum string length
        */
        static void writeNumericString(Buffer *s, const string &num_str, int min)
        {
            int mlength;
            uint8_t num, c1, c2;

            mlength = (num_str.length() - min >= 0) ? num_str.length() - min : min;
            writeLength(s, mlength);

            for (size_t i = 0; i < num_str.length(); ++i) {
                c1 = num_str[i];
                c2 = ((i + 1) < num_str.length()) ? num_str[i + 1] : 0x30;

                c1 = (c1 - 0x30) % 10;
                c2 = (c2 - 0x30) % 10;
                num = (c1 << 4) | c2;

                s->appendUInt8(num); /* string */
            }
        }

        /**
        * Read PER padding with zeros.
        * @param s stream
        * @param length
        */
        static bool readPadding(Buffer *s, int length)
        {
            if (((int)s->length()) < length)
                return false;

            s->retrieve(length);
            return true;
        }

        /**
        * Write PER padding with zeros.
        * @param s stream
        * @param length
        */
        static void writePadding(Buffer *s, int length)
        {
            s->append(length, '\0');
        }

        /**
        * Read PER OCTET_STRING.
        * @param s stream
        * @param oct_str octet string
        * @param length string length
        * @param min minimum length
        * @return
        */
        static bool readOctetStream(Buffer *s, const string &oct_str, int min)
        {
            uint16_t mlength;
            const char *a_oct_str;

            if (!readLength(s, mlength))
                return false;
            if (mlength + min != oct_str.length())
                return false;
            if (((int)s->length()) < oct_str.length())
                return false;

            a_oct_str = (const char *)s->data();
            s->retrieve(oct_str.length());

            for (size_t i = 0; i < oct_str.length(); ++i) {
                if (a_oct_str[i] != oct_str[i])
                    return false;
            }
            return true;
        }

        /**
        * Write PER OCTET_STRING
        * @param s stream
        * @param oct_str octet string
        * @param length string length
        * @param min minimum string length
        */
        static void writeOctetStream(Buffer *s, const string &oct_str, int min = 0)
        {
            int mlength = (oct_str.length() - min >= 0) ? oct_str.length() - min : min;

            writeLength(s, mlength);
            for (size_t i = 0; i < oct_str.length(); ++i)
                s->appendUInt8(oct_str[i]);
        }
    };

} // namespace rdpp

#endif // _RDPP_CORE_PER_H_
