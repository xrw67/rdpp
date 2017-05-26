/* three seperate function for speed when decompressing the bitmaps
   when modifing one function make the change in the others
   jay.sorg@gmail.com 
*/

#include <core/bitmap.h>
#include <core/log.h>
#include <math.h>

#define TAG "BMP"

using namespace rdpp;

namespace {

	#define CVAL(p)   (*(p++))
	#ifdef NEED_ALIGN
	#ifdef L_ENDIAN
	#define CVAL2(p, v) { v = (*(p++)); v |= (*(p++)) << 8; }
	#else
	#define CVAL2(p, v) { v = (*(p++)) << 8; v |= (*(p++)); }
	#endif /* L_ENDIAN */
	#else
	#define CVAL2(p, v) { v = (*((uint16_t*)p)); p += 2; }
	#endif /* NEED_ALIGN */

	#define UNROLL8(exp) { exp exp exp exp exp exp exp exp }

	#define REPEAT(statement) \
	{ \
		while((count & ~0x7) && ((x+8) < width)) \
			UNROLL8( statement; count--; x++; ); \
		\
		while((count > 0) && (x < width)) \
		{ \
			statement; \
			count--; \
			x++; \
		} \
	}

	#define MASK_UPDATE() \
	{ \
		mixmask <<= 1; \
		if (mixmask == 0) \
		{ \
			mask = fom_mask ? fom_mask : CVAL(input); \
			mixmask = 1; \
		} \
	}

	/* 1 byte bitmap decompress */
	static bool
	bitmap_decompress1(uint8_t * output, int width, int height, uint8_t * input, int size)
	{
		uint8_t *end = input + size;
		uint8_t *prevline = NULL, *line = NULL;
		int opcode, count, offset, isfillormix, x = width;
		int lastopcode = -1, insertmix = false, bicolour = false;
		uint8_t code;
		uint8_t colour1 = 0, colour2 = 0;
		uint8_t mixmask, mask = 0;
		uint8_t mix = 0xff;
		int fom_mask = 0;

		while (input < end)
		{
			fom_mask = 0;
			code = CVAL(input);
			opcode = code >> 4;
			/* Handle different opcode forms */
			switch (opcode)
			{
				case 0xc:
				case 0xd:
				case 0xe:
					opcode -= 6;
					count = code & 0xf;
					offset = 16;
					break;
				case 0xf:
					opcode = code & 0xf;
					if (opcode < 9)
					{
						count = CVAL(input);
						count |= CVAL(input) << 8;
					}
					else
					{
						count = (opcode < 0xb) ? 8 : 1;
					}
					offset = 0;
					break;
				default:
					opcode >>= 1;
					count = code & 0x1f;
					offset = 32;
					break;
			}
			/* Handle strange cases for counts */
			if (offset != 0)
			{
				isfillormix = ((opcode == 2) || (opcode == 7));
				if (count == 0)
				{
					if (isfillormix)
						count = CVAL(input) + 1;
					else
						count = CVAL(input) + offset;
				}
				else if (isfillormix)
				{
					count <<= 3;
				}
			}
			/* Read preliminary data */
			switch (opcode)
			{
				case 0:	/* Fill */
					if ((lastopcode == opcode) && !((x == width) && (prevline == NULL)))
						insertmix = true;
					break;
				case 8:	/* Bicolour */
					colour1 = CVAL(input);
				case 3:	/* Colour */
					colour2 = CVAL(input);
					break;
				case 6:	/* SetMix/Mix */
				case 7:	/* SetMix/FillOrMix */
					mix = CVAL(input);
					opcode -= 5;
					break;
				case 9:	/* FillOrMix_1 */
					mask = 0x03;
					opcode = 0x02;
					fom_mask = 3;
					break;
				case 0x0a:	/* FillOrMix_2 */
					mask = 0x05;
					opcode = 0x02;
					fom_mask = 5;
					break;
			}
			lastopcode = opcode;
			mixmask = 0;
			/* Output body */
			while (count > 0)
			{
				if (x >= width)
				{
					if (height <= 0)
						return false;
					x = 0;
					height--;
					prevline = line;
					line = output + height * width;
				}
				switch (opcode)
				{
					case 0:	/* Fill */
						if (insertmix)
						{
							if (prevline == NULL)
								line[x] = mix;
							else
								line[x] = prevline[x] ^ mix;
							insertmix = false;
							count--;
							x++;
						}
						if (prevline == NULL)
						{
							REPEAT(line[x] = 0)
						}
						else
						{
							REPEAT(line[x] = prevline[x])
						}
						break;
					case 1:	/* Mix */
						if (prevline == NULL)
						{
							REPEAT(line[x] = mix)
						}
						else
						{
							REPEAT(line[x] = prevline[x] ^ mix)
						}
						break;
					case 2:	/* Fill or Mix */
						if (prevline == NULL)
						{
							REPEAT
							(
								MASK_UPDATE();
								if (mask & mixmask)
									line[x] = mix;
								else
									line[x] = 0;
							)
						}
						else
						{
							REPEAT
							(
								MASK_UPDATE();
								if (mask & mixmask)
									line[x] = prevline[x] ^ mix;
								else
									line[x] = prevline[x];
							)
						}
						break;
					case 3:	/* Colour */
						REPEAT(line[x] = colour2)
						break;
					case 4:	/* Copy */
						REPEAT(line[x] = CVAL(input))
						break;
					case 8:	/* Bicolour */
						REPEAT
						(
							if (bicolour)
							{
								line[x] = colour2;
								bicolour = false;
							}
							else
							{
								line[x] = colour1;
								bicolour = true; count++;
							}
						)
						break;
					case 0xd:	/* White */
						REPEAT(line[x] = 0xff)
						break;
					case 0xe:	/* Black */
						REPEAT(line[x] = 0)
						break;
					default:
						RDPP_LOG(TAG, INFO) << "unimpl bitmap opcode 0x" << (void *)opcode;
						return false;
				}
			}
		}
		return true;
	}

	/* 2 byte bitmap decompress */
	static bool
	bitmap_decompress2(uint8_t * output, int width, int height, uint8_t * input, int size)
	{
		uint8_t *end = input + size;
		uint16_t *prevline = NULL, *line = NULL;
		int opcode, count, offset, isfillormix, x = width;
		int lastopcode = -1, insertmix = false, bicolour = false;
		uint8_t code;
		uint16_t colour1 = 0, colour2 = 0;
		uint8_t mixmask, mask = 0;
		uint16_t mix = 0xffff;
		int fom_mask = 0;

		while (input < end)
		{
			fom_mask = 0;
			code = CVAL(input);
			opcode = code >> 4;
			/* Handle different opcode forms */
			switch (opcode)
			{
				case 0xc:
				case 0xd:
				case 0xe:
					opcode -= 6;
					count = code & 0xf;
					offset = 16;
					break;
				case 0xf:
					opcode = code & 0xf;
					if (opcode < 9)
					{
						count = CVAL(input);
						count |= CVAL(input) << 8;
					}
					else
					{
						count = (opcode < 0xb) ? 8 : 1;
					}
					offset = 0;
					break;
				default:
					opcode >>= 1;
					count = code & 0x1f;
					offset = 32;
					break;
			}
			/* Handle strange cases for counts */
			if (offset != 0)
			{
				isfillormix = ((opcode == 2) || (opcode == 7));
				if (count == 0)
				{
					if (isfillormix)
						count = CVAL(input) + 1;
					else
						count = CVAL(input) + offset;
				}
				else if (isfillormix)
				{
					count <<= 3;
				}
			}
			/* Read preliminary data */
			switch (opcode)
			{
				case 0:	/* Fill */
					if ((lastopcode == opcode) && !((x == width) && (prevline == NULL)))
						insertmix = true;
					break;
				case 8:	/* Bicolour */
					CVAL2(input, colour1);
				case 3:	/* Colour */
					CVAL2(input, colour2);
					break;
				case 6:	/* SetMix/Mix */
				case 7:	/* SetMix/FillOrMix */
					CVAL2(input, mix);
					opcode -= 5;
					break;
				case 9:	/* FillOrMix_1 */
					mask = 0x03;
					opcode = 0x02;
					fom_mask = 3;
					break;
				case 0x0a:	/* FillOrMix_2 */
					mask = 0x05;
					opcode = 0x02;
					fom_mask = 5;
					break;
			}
			lastopcode = opcode;
			mixmask = 0;
			/* Output body */
			while (count > 0)
			{
				if (x >= width)
				{
					if (height <= 0)
						return false;
					x = 0;
					height--;
					prevline = line;
					line = ((uint16_t *) output) + height * width;
				}
				switch (opcode)
				{
					case 0:	/* Fill */
						if (insertmix)
						{
							if (prevline == NULL)
								line[x] = mix;
							else
								line[x] = prevline[x] ^ mix;
							insertmix = false;
							count--;
							x++;
						}
						if (prevline == NULL)
						{
							REPEAT(line[x] = 0)
						}
						else
						{
							REPEAT(line[x] = prevline[x])
						}
						break;
					case 1:	/* Mix */
						if (prevline == NULL)
						{
							REPEAT(line[x] = mix)
						}
						else
						{
							REPEAT(line[x] = prevline[x] ^ mix)
						}
						break;
					case 2:	/* Fill or Mix */
						if (prevline == NULL)
						{
							REPEAT
							(
								MASK_UPDATE();
								if (mask & mixmask)
									line[x] = mix;
								else
									line[x] = 0;
							)
						}
						else
						{
							REPEAT
							(
								MASK_UPDATE();
								if (mask & mixmask)
									line[x] = prevline[x] ^ mix;
								else
									line[x] = prevline[x];
							)
						}
						break;
					case 3:	/* Colour */
						REPEAT(line[x] = colour2)
						break;
					case 4:	/* Copy */
						REPEAT(CVAL2(input, line[x]))
						break;
					case 8:	/* Bicolour */
						REPEAT
						(
							if (bicolour)
							{
								line[x] = colour2;
								bicolour = false;
							}
							else
							{
								line[x] = colour1;
								bicolour = true;
								count++;
							}
						)
						break;
					case 0xd:	/* White */
						REPEAT(line[x] = 0xffff)
						break;
					case 0xe:	/* Black */
						REPEAT(line[x] = 0)
						break;
					default:
						RDPP_LOG(TAG, INFO) << "unimpl bitmap opcode 0x" << (void *)opcode;
						return false;
				}
			}
		}
		return true;
	}

	/* 3 byte bitmap decompress */
	static bool
	bitmap_decompress3(uint8_t * output, int width, int height, uint8_t * input, int size)
	{
		uint8_t *end = input + size;
		uint8_t *prevline = NULL, *line = NULL;
		int opcode, count, offset, isfillormix, x = width;
		int lastopcode = -1, insertmix = false, bicolour = false;
		uint8_t code;
		uint8_t colour1[3] = {0, 0, 0}, colour2[3] = {0, 0, 0};
		uint8_t mixmask, mask = 0;
		uint8_t mix[3] = {0xff, 0xff, 0xff};
		int fom_mask = 0;

		while (input < end)
		{
			fom_mask = 0;
			code = CVAL(input);
			opcode = code >> 4;
			/* Handle different opcode forms */
			switch (opcode)
			{
				case 0xc:
				case 0xd:
				case 0xe:
					opcode -= 6;
					count = code & 0xf;
					offset = 16;
					break;
				case 0xf:
					opcode = code & 0xf;
					if (opcode < 9)
					{
						count = CVAL(input);
						count |= CVAL(input) << 8;
					}
					else
					{
						count = (opcode <
							 0xb) ? 8 : 1;
					}
					offset = 0;
					break;
				default:
					opcode >>= 1;
					count = code & 0x1f;
					offset = 32;
					break;
			}
			/* Handle strange cases for counts */
			if (offset != 0)
			{
				isfillormix = ((opcode == 2) || (opcode == 7));
				if (count == 0)
				{
					if (isfillormix)
						count = CVAL(input) + 1;
					else
						count = CVAL(input) + offset;
				}
				else if (isfillormix)
				{
					count <<= 3;
				}
			}
			/* Read preliminary data */
			switch (opcode)
			{
				case 0:	/* Fill */
					if ((lastopcode == opcode) && !((x == width) && (prevline == NULL)))
						insertmix = true;
					break;
				case 8:	/* Bicolour */
					colour1[0] = CVAL(input);
					colour1[1] = CVAL(input);
					colour1[2] = CVAL(input);
				case 3:	/* Colour */
					colour2[0] = CVAL(input);
					colour2[1] = CVAL(input);
					colour2[2] = CVAL(input);
					break;
				case 6:	/* SetMix/Mix */
				case 7:	/* SetMix/FillOrMix */
					mix[0] = CVAL(input);
					mix[1] = CVAL(input);
					mix[2] = CVAL(input);
					opcode -= 5;
					break;
				case 9:	/* FillOrMix_1 */
					mask = 0x03;
					opcode = 0x02;
					fom_mask = 3;
					break;
				case 0x0a:	/* FillOrMix_2 */
					mask = 0x05;
					opcode = 0x02;
					fom_mask = 5;
					break;
			}
			lastopcode = opcode;
			mixmask = 0;
			/* Output body */
			while (count > 0)
			{
				if (x >= width)
				{
					if (height <= 0)
						return false;
					x = 0;
					height--;
					prevline = line;
					line = output + height * (width * 3);
				}
				switch (opcode)
				{
					case 0:	/* Fill */
						if (insertmix)
						{
							if (prevline == NULL)
							{
								line[x * 3] = mix[0];
								line[x * 3 + 1] = mix[1];
								line[x * 3 + 2] = mix[2];
							}
							else
							{
								line[x * 3] =
								 prevline[x * 3] ^ mix[0];
								line[x * 3 + 1] =
								 prevline[x * 3 + 1] ^ mix[1];
								line[x * 3 + 2] =
								 prevline[x * 3 + 2] ^ mix[2];
							}
							insertmix = false;
							count--;
							x++;
						}
						if (prevline == NULL)
						{
							REPEAT
							(
								line[x * 3] = 0;
								line[x * 3 + 1] = 0;
								line[x * 3 + 2] = 0;
							)
						}
						else
						{
							REPEAT
							(
								line[x * 3] = prevline[x * 3];
								line[x * 3 + 1] = prevline[x * 3 + 1];
								line[x * 3 + 2] = prevline[x * 3 + 2];
							)
						}
						break;
					case 1:	/* Mix */
						if (prevline == NULL)
						{
							REPEAT
							(
								line[x * 3] = mix[0];
								line[x * 3 + 1] = mix[1];
								line[x * 3 + 2] = mix[2];
							)
						}
						else
						{
							REPEAT
							(
								line[x * 3] =
								 prevline[x * 3] ^ mix[0];
								line[x * 3 + 1] =
								 prevline[x * 3 + 1] ^ mix[1];
								line[x * 3 + 2] =
								 prevline[x * 3 + 2] ^ mix[2];
							)
						}
						break;
					case 2:	/* Fill or Mix */
						if (prevline == NULL)
						{
							REPEAT
							(
								MASK_UPDATE();
								if (mask & mixmask)
								{
									line[x * 3] = mix[0];
									line[x * 3 + 1] = mix[1];
									line[x * 3 + 2] = mix[2];
								}
								else
								{
									line[x * 3] = 0;
									line[x * 3 + 1] = 0;
									line[x * 3 + 2] = 0;
								}
							)
						}
						else
						{
							REPEAT
							(
								MASK_UPDATE();
								if (mask & mixmask)
								{
									line[x * 3] =
									 prevline[x * 3] ^ mix [0];
									line[x * 3 + 1] =
									 prevline[x * 3 + 1] ^ mix [1];
									line[x * 3 + 2] =
									 prevline[x * 3 + 2] ^ mix [2];
								}
								else
								{
									line[x * 3] =
									 prevline[x * 3];
									line[x * 3 + 1] =
									 prevline[x * 3 + 1];
									line[x * 3 + 2] =
									 prevline[x * 3 + 2];
								}
							)
						}
						break;
					case 3:	/* Colour */
						REPEAT
						(
							line[x * 3] = colour2 [0];
							line[x * 3 + 1] = colour2 [1];
							line[x * 3 + 2] = colour2 [2];
						)
						break;
					case 4:	/* Copy */
						REPEAT
						(
							line[x * 3] = CVAL(input);
							line[x * 3 + 1] = CVAL(input);
							line[x * 3 + 2] = CVAL(input);
						)
						break;
					case 8:	/* Bicolour */
						REPEAT
						(
							if (bicolour)
							{
								line[x * 3] = colour2[0];
								line[x * 3 + 1] = colour2[1];
								line[x * 3 + 2] = colour2[2];
								bicolour = false;
							}
							else
							{
								line[x * 3] = colour1[0];
								line[x * 3 + 1] = colour1[1];
								line[x * 3 + 2] = colour1[2];
								bicolour = true;
								count++;
							}
						)
						break;
					case 0xd:	/* White */
						REPEAT
						(
							line[x * 3] = 0xff;
							line[x * 3 + 1] = 0xff;
							line[x * 3 + 2] = 0xff;
						)
						break;
					case 0xe:	/* Black */
						REPEAT
						(
							line[x * 3] = 0;
							line[x * 3 + 1] = 0;
							line[x * 3 + 2] = 0;
						)
						break;
					default:
						RDPP_LOG(TAG, INFO) << "unimpl bitmap opcode 0x" << (void *)opcode;
						return false;
				}
			}
		}
		return true;
	}

	/* decompress a colour plane */
	static int
	process_plane(uint8_t * in, int width, int height, uint8_t * out, int size)
	{
		int indexw;
		int indexh;
		int code;
		int collen;
		int replen;
		int color;
		int x;
		int revcode;
		uint8_t * last_line;
		uint8_t * this_line;
		uint8_t * org_in;
		uint8_t * org_out;

		org_in = in;
		org_out = out;
		last_line = 0;
		indexh = 0;
		while (indexh < height)
		{
			out = (org_out + width * height * 4) - ((indexh + 1) * width * 4);
			color = 0;
			this_line = out;
			indexw = 0;
			if (last_line == 0)
			{
				while (indexw < width)
				{
					code = CVAL(in);
					replen = code & 0xf;
					collen = (code >> 4) & 0xf;
					revcode = (replen << 4) | collen;
					if ((revcode <= 47) && (revcode >= 16))
					{
						replen = revcode;
						collen = 0;
					}
					while (collen > 0)
					{
						color = CVAL(in);
						*out = color;
						out += 4;
						indexw++;
						collen--;
					}
					while (replen > 0)
					{
						*out = color;
						out += 4;
						indexw++;
						replen--;
					}
				}
			}
			else
			{
				while (indexw < width)
				{
					code = CVAL(in);
					replen = code & 0xf;
					collen = (code >> 4) & 0xf;
					revcode = (replen << 4) | collen;
					if ((revcode <= 47) && (revcode >= 16))
					{
						replen = revcode;
						collen = 0;
					}
					while (collen > 0)
					{
						x = CVAL(in);
						if (x & 1)
						{
							x = x >> 1;
							x = x + 1;
							color = -x;
						}
						else
						{
							x = x >> 1;
							color = x;
						}
						x = last_line[indexw * 4] + color;
						*out = x;
						out += 4;
						indexw++;
						collen--;
					}
					while (replen > 0)
					{
						x = last_line[indexw * 4] + color;
						*out = x;
						out += 4;
						indexw++;
						replen--;
					}
				}
			}
			indexh++;
			last_line = this_line;
		}
		return (int) (in - org_in);
	}

	/* 4 byte bitmap decompress */
	static bool
	bitmap_decompress4(uint8_t * output, int width, int height, uint8_t * input, int size)
	{
		int code;
		int bytes_pro;
		int total_pro;

		code = CVAL(input);
		if (code != 0x10)
		{
			return false;
		}
		total_pro = 1;
		bytes_pro = process_plane(input, width, height, output + 3, size - total_pro);
		total_pro += bytes_pro;
		input += bytes_pro;
		bytes_pro = process_plane(input, width, height, output + 2, size - total_pro);
		total_pro += bytes_pro;
		input += bytes_pro;
		bytes_pro = process_plane(input, width, height, output + 1, size - total_pro);
		total_pro += bytes_pro;
		input += bytes_pro;
		bytes_pro = process_plane(input, width, height, output + 0, size - total_pro);
		total_pro += bytes_pro;
		return size == total_pro;
	}

} // namespace

/* main decompress function */
bool Bitmap::decompress(uint8_t *output, int width, int height, 
	                    uint8_t *input, int size, int Bpp)
{
	bool rv = false;

	switch (Bpp) {
		case 1:
			rv = bitmap_decompress1(output, width, height, input, size);
			break;
		case 2:
			rv = bitmap_decompress2(output, width, height, input, size);
			break;
		case 3:
			rv = bitmap_decompress3(output, width, height, input, size);
			break;
		case 4:
			rv = bitmap_decompress4(output, width, height, input, size);
			break;
		default:
			RDPP_LOG(TAG, INFO) << "unimpl Bpp " << Bpp;
			break;
	}
	return rv;
}

string Bitmap::decompress(int width, int height, 
					      const string &input, int Bpp)
{
	string output(width * height * Bpp, '\0');

	if (decompress((uint8_t *)output.c_str(), width, height,
		              (uint8_t *)input.c_str(), input.length(), Bpp))
		return output;
	else
		return "";
}

int Bitmap::bitsPerPixel2Bpp(int bitsPerPixel)
{
	switch (bitsPerPixel) {
	case 8:
		return 1;
	case 15:
	case 16:
		return 2;
	case 24:
		return 3;
	case 32:
		return 4;
	default:
		RDPP_LOG(TAG, INFO) << "unimpl bitsPerPixel: " << bitsPerPixel;
		return 0;
	}
}
