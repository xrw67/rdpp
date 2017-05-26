/**
 * Remote Session Scenario File format
 * Private protocol format to save events
 */

#ifndef _RDPP_CORE_RSS_H_
#define _RDPP_CORE_RSS_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/timestamp.h>
#include <stdlib.h>

#ifdef WIN32
#else
#include <unistd.h>
#endif

namespace rdpp {

#include <core/pshpack1.h>

	/// @summary: event type
	enum EventType {
		RSS_EVENT_UPDATE = 0x0001,
		RSS_EVENT_SCREEN = 0x0002,
		RSS_EVENT_INFO = 0x0003,
		RSS_EVENT_CLOSE = 0x0004,
		RSS_EVENT_KEY_UNICODE = 0x0005,
		RSS_EVENT_KEY_SCANCODE = 0x0006,
	};

	/// @summary: format of update bitmap
	enum UpdateFormat {
		RSS_UPDATE_RAW = 0x01,
		RSS_UPDATE_BMP = 0x02,
	};
	
	struct RssHeader {
		uint32_t magic;
		uint8_t version;
		uint64_t timestamp;

		RssHeader() : magic('RSS\0'), version(1) {}
	};

	struct Event {
		uint16_t type;
		uint32_t timestemp;
		uint32_t length;
	};

	/// @summary: Update event
	struct UpdateEvent {
		uint16_t destLeft;
		uint16_t destTop;
		uint16_t destRight;
		uint16_t destBottom;
		uint16_t width;
		uint16_t height;
		uint8_t bpp;
		uint8_t format;
		uint32_t length; // data length
		string data;

		void read(Buffer &s)
		{
			destLeft = s.readUInt16();
			destTop = s.readUInt16();
			destRight = s.readUInt16();
			destBottom = s.readUInt16();
			width = s.readUInt16();
			height = s.readUInt16();
			bpp = s.readUInt8();
			format = s.readUInt8();
			length = s.readUInt32();
			data = s.retrieveAsString(length);
		}

		void write(Buffer &s)
		{
			assert(length == data.length());

			s.appendUInt16(destLeft);
			s.appendUInt16(destTop);
			s.appendUInt16(destRight);
			s.appendUInt16(destBottom);
			s.appendUInt16(width);
			s.appendUInt16(height);
			s.appendUInt8(bpp);
			s.appendUInt8(format);
			s.appendUInt32(length);
			s.append(data);
		}
	};

	/// @summary: Info event
	struct InfoEvent {
		uint16_t usernameLength;
		string username;
		uint16_t passwordLength;
		string password;
		uint16_t domainLength;
		string domain;
		uint16_t hostnameLength;
		string hostname;

		void read(Buffer &s)
		{
			usernameLength = s.readUInt16();
			username = s.retrieveAsString(usernameLength);
			passwordLength = s.readUInt16();
			password = s.retrieveAsString(passwordLength);
			domainLength = s.readUInt16();
			domain = s.retrieveAsString(domainLength);
			hostnameLength = s.readUInt16();
			hostname = s.retrieveAsString(hostnameLength);
		}

		void write(Buffer &s)
		{
			assert(usernameLength == username.length());
			assert(passwordLength == password.length());
			assert(domainLength == domain.length());
			assert(hostnameLength == hostname.length());

			s.appendUInt16(usernameLength);
			s.append(username);
			s.appendUInt16(passwordLength);
			s.append(password);
			s.appendUInt16(domainLength);
			s.append(domain);
			s.appendUInt16(hostnameLength);
			s.append(hostname);
		}
	};

	/// @summary: screen information event
	struct ScreenEvent {
		uint16_t width;
		uint16_t height;
		uint8_t colorDepth;
	};

	/// @summary: end of session event
	struct CloseEvent {
	};

	/// @summary: keyboard event (keylogger) as unicode event
	struct KeyEventUnicode {
		uint32_t code;
		uint8_t isPressed;
	};

	/// @summary: keyboard event (keylogger)
	struct KeyEventScancode {
		uint32_t code;
		uint8_t isPressed;
	};

#include <core/poppack.h>

	/// @summary: RSS File recorder
	class FileRecorder
	{
	public:
		/// @param f : {file} file pointer use to write
		FileRecorder(const string &filename);
		~FileRecorder();

		/// @summary: save event in file
		bool rec(uint16_t eventType, const Buffer &eventData);

		/// @summary: record update event
		/// @param destLeft: {int} xmin position
		/// @param destTop : {int} ymin position
		/// @param destRight : {int} xmax position because RDP can send bitmap with padding
		/// @param destBottom : {int} ymax position because RDP can send bitmap with padding
		/// @param width : {int} width of bitmap
		/// @param height : {int} height of bitmap
		/// @param bpp : {int} number of bit per pixel
		/// @param upateFormat : {UpdateFormat} use RLE compression
		/// @param data : {str} bitmap data
		bool update(uint16_t destLeft, uint16_t destTop, 
			        uint16_t destRight, uint16_t destBottom, 
			        uint16_t width, uint16_t height, uint8_t bpp, 
			        uint8_t upateFormat, const string &data);

		/// @summary: record resize event of screen(maybe first event)
		/// @param width: {int} width of screen
		/// @param height : {int} height of screen
		/// @param colorDepth : {int} colorDepth
		bool screen(uint16_t width, uint16_t height, uint8_t colorDepth);

		/// @summary: Record informations event
		/// @param username: {str} username of session
		/// @param password : {str} password of session
		/// @param domain : {str} domain of session
		/// @param hostname : {str} hostname of session
		bool credentials(const string &username, const string & password,
			             const string &domain = "", const string &hostname = "");

		/// @summary: record key event as unicode
		/// @param code: unicode code
		/// @param isPressed : True if a key press event
		bool keyUnicode(uint32_t code, uint8_t isPressed);

		/// @summary: record key event as scancode
		/// @param code: scancode code
		/// @param isPressed : True if a key press event
		bool keyScancode(uint32_t code, uint8_t isPressed);

		/// @summary: end of scenario
		bool close(void);

	private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(FileRecorder);

		bool write(const void *data, size_t len);

		FILE *_fp;
		char _buffer[64 *1024];
		Timestamp _lastEventTimer;

		static const int _kFlushPerMilliSeconds = 5000;
	};

	/// @summary: RSS File reader
	class FileReader
	{
	public:
		/// @param f: {file} file pointer use to read
		FileReader(const string &filename);
		~FileReader();

		bool header(RssHeader *hdr);

		/// @summary: read next event and return it
		bool nextEvent(Event *e, Buffer *eventData);

	private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(FileReader);

		bool read(void *buf, size_t len);
		FILE *_fp;
	};

} // namespace rdpp

#endif // _RDPP_CORE_RSS_H_
