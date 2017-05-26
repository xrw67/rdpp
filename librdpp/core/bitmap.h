#ifndef _RDPP_CORE_BITMAP_H_
#define _RDPP_CORE_BITMAP_H_

#include <core/config.h>

namespace rdpp {

class Bitmap
{
public:
	static bool decompress(uint8_t *output, int width, int height, 
					       uint8_t *input, int size, int Bpp);

	static string decompress(int width, int height, 
					         const string &input, int Bpp);

	static int bitsPerPixel2Bpp(int bitsPerPixel);
};

} // namespace rdpp

#endif // _RDPP_CORE_BITMAP_H_
