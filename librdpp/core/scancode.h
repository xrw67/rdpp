#ifndef _RDPP_CORE_SCANCODE_H_
#define _RDPP_CORE_SCANCODE_H_

#include <core/config.h>

namespace rdpp {

	///	@summary: try to convert native code to char code
	///	@return: char
	static char scancodeToChar(uint32_t code)
	{
		switch (code) {
		case 0x10: return 'q';
		case 0x11: return 'w';
		case 0x12: return 'e';
		case 0x13: return 'r';
		case 0x14: return 't';
		case 0x15: return 'y';
		case 0x16: return 'u';
		case 0x17: return 'i';
		case 0x18: return 'o';
		case 0x19: return 'p';
		case 0x1e: return 'a';
		case 0x1f: return 's';
		case 0x20: return 'd';
		case 0x21: return 'f';
		case 0x22: return 'g';
		case 0x23: return 'h';
		case 0x24: return 'j';
		case 0x25: return 'k';
		case 0x26: return 'l';
		case 0x2c: return 'z';
		case 0x2d: return 'x';
		case 0x2e: return 'c';
		case 0x2f: return 'v';
		case 0x30: return 'b';
		case 0x31: return 'n';
		case 0x32: return 'm';
		}

		RDPP_LOG("SCANCODE", INFO) << "unknown scancode " << (void *)code;
		return '\0';
	}
} // namespace rdpp

#endif // _RDPP_CORE_SCANCODE_H_
