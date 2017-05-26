#include <core/rss.h>
#include <core/log.h>

#define TAG "RSS"

using namespace rdpp;

//
// FileRecorder
//

FileRecorder::FileRecorder(const string &filename)
	: _fp(::fopen(filename.data(), "wb"))
	, _lastEventTimer(Timestamp::now())
{
	RDPP_LOG(TAG, INFO) << "RSS Filename: " << filename;

	::setvbuf(_fp, _buffer, _IOFBF, sizeof(_buffer));

	RssHeader hdr;
	hdr.timestamp = _lastEventTimer.timestamp();

	write(&hdr, sizeof(hdr));
}

FileRecorder::~FileRecorder()
{
	if (_fp) {
		::fclose(_fp);
		_fp = NULL;
	}
}

bool FileRecorder::rec(uint16_t eventType, const Buffer &eventData)
{
	Event hdr;
	Timestamp now(Timestamp::now());

	hdr.type = eventType;
	hdr.length = sizeof(hdr) + eventData.length();
	hdr.timestemp = (uint32_t)(now.timestamp() - _lastEventTimer.timestamp());
	_lastEventTimer = now;

	if (!write(&hdr, sizeof(hdr)))
		return false;
	if (!write(eventData.data(), eventData.length()))
		return false;

	if (hdr.timestemp >= _kFlushPerMilliSeconds)
		::fflush(_fp);

	return true;
}

bool FileRecorder::update(uint16_t destLeft, uint16_t destTop, 
						  uint16_t destRight, uint16_t destBottom, 
						  uint16_t width, uint16_t height, uint8_t bpp, 
						  uint8_t upateFormat, const string &data)
{
	Buffer s;
	UpdateEvent updateEvent;
	
	updateEvent.destLeft = destLeft;
    updateEvent.destTop = destTop;
    updateEvent.destRight = destRight;
    updateEvent.destBottom = destBottom;
    updateEvent.width = width;
    updateEvent.height = height;
    updateEvent.bpp = bpp;
    updateEvent.format = upateFormat;
	updateEvent.length = data.length();
    updateEvent.data = data;

	updateEvent.write(s);

	return rec(RSS_EVENT_UPDATE, s);
}

bool FileRecorder::screen(uint16_t width, uint16_t height, uint8_t colorDepth)
{
	Buffer s;
	ScreenEvent screenEvent;

	screenEvent.width = width;
	screenEvent.height = height;
	screenEvent.colorDepth = colorDepth;

	s.append(&screenEvent, sizeof(screenEvent));

	return rec(RSS_EVENT_SCREEN, s);
}

bool FileRecorder::credentials(const string &username, const string &password,
							   const string &domain, const string &hostname)
{
	Buffer s;
	InfoEvent infoEvent;

	infoEvent.usernameLength = username.length();
	infoEvent.username = username;
	infoEvent.passwordLength = password.length();
	infoEvent.password = password;
	infoEvent.domainLength = domain.length();
	infoEvent.domain = domain;
	infoEvent.hostnameLength = hostname.length();
	infoEvent.hostname = hostname;

	infoEvent.write(s);

	return rec(RSS_EVENT_INFO, s);
}


bool FileRecorder::keyUnicode(uint32_t code, uint8_t isPressed)
{
	Buffer s;
	KeyEventUnicode keyEvent;

	keyEvent.code = code;
	keyEvent.isPressed = isPressed;

	s.append(&keyEvent, sizeof(keyEvent));

	return rec(RSS_EVENT_KEY_UNICODE, s);
}


bool FileRecorder::keyScancode(uint32_t code, uint8_t isPressed)
{
	Buffer s;
	KeyEventScancode keyEvent;

	keyEvent.code = code;
	keyEvent.isPressed = isPressed;

	s.append(&keyEvent, sizeof(keyEvent));

	return rec(RSS_EVENT_KEY_SCANCODE, s);
}

bool FileRecorder::close(void)
{
	Buffer s;
	return rec(RSS_EVENT_CLOSE, s);
}

bool FileRecorder::write(const void *data, size_t len)
{
	if (!_fp)
		return false;
	if (!data || len == 0)
		return true;
	
	const char *p = (const char *)data;

	size_t n = ::fwrite(p, 1, len, _fp);
	size_t remain = len - n;
	while (remain > 0) {
		size_t x = ::fwrite(p + n, 1, remain, _fp);
		if (x == 0) {
			int err = ::ferror(_fp);
			if (err)
				return false;
			break;
		}
		n += x;
		remain = len - n;
	}
	return true;
}

//
// FileReader
//

FileReader::FileReader(const string &filename)
	: _fp(::fopen(filename.data(), "rb"))
{
}

FileReader::~FileReader()
{
	::fclose(_fp);
}

bool FileReader::header(RssHeader *hdr)
{
	return read(hdr, sizeof(RssHeader));
}

bool FileReader::nextEvent(Event *e, Buffer *eventData)
{
	if (!read(e, sizeof(Event)))
		return false;
	
	size_t dataLength = e->length - sizeof(Event);

	eventData->clear();
	eventData->ensureWritableBytes(dataLength);
	if (!read(eventData->beginWrite(), dataLength))
		return false;

	eventData->hasWritten(dataLength);
	return true;
}

bool FileReader::read(void *buf, size_t len)
{
	if (!buf || len == 0)
		return true;

	char *p = (char *)buf;

	size_t n = ::fread(p, 1, len, _fp);
	size_t remain = len - n;
	while (remain > 0) {
		size_t x = ::fread(p + n, 1, remain, _fp);
		if (x == 0) {
			int err = ::ferror(_fp);
			if (err)
				return false;
			break;
		}
		n += x;
		remain = len -n;
	}
	return true;
}
