#include <rdp/rdp.h>
#include <rdp/pdu/layer.h>
#include <rdp/pdu/data.h>
#include <rdp/lic.h>
#include <rdp/sec.h>
#include <rdp/t125/gcc.h>
#include <rdp/t125/mcs.h>
#include <rdp/x224.h>
#include <rdp/tpkt.h>
#include <rdp/nla/cssp.h>
#include <rdp/nla/ntlm.h>
#include <algorithm>

#define TAG "RDP"

using namespace rdpp;

//
// RDPClientController
//

RDPClientController::RDPClientController(RdpTransport *rdpTransport)
    : _isReady(false)
	, _ssl(NULL)
{
    // set layer stack
    _pduLayer = new ClientPDULayer(this);
    _secLayer = new ClientSecLayer(_pduLayer, _pduLayer);
    _mcsLayer = new ClientMCSLayer(_secLayer);
    _x224Layer = new ClientX224Layer(_mcsLayer, rdpTransport, this);

    _tpktLayer = new TPKTLayer(_x224Layer, _secLayer, rdpTransport);

	_ntlm = new NTLMv2();
	_cssp = new CSSP(_tpktLayer, _mcsLayer, _ntlm, rdpTransport);
    _secLayer->init();
}

RDPClientController::~RDPClientController()
{
    delete _pduLayer;
    delete _secLayer;
    delete _mcsLayer;
    delete _x224Layer;
    delete _tpktLayer;
	delete _ntlm;
	delete _cssp;
}

void RDPClientController::addClientObserver(RDPClientObserver *observer)
{
	RDPClientObserverList::iterator it;

	it = std::find(_clientObservers.begin(), _clientObservers.end(), observer);
	if (it == _clientObservers.end())
		_clientObservers.push_back(observer);
}

void RDPClientController::removeClientObserver(RDPClientObserver *observer)
{
	RDPClientObserverList::iterator it;

	it = std::find(_clientObservers.begin(), _clientObservers.end(), observer);
	if (it == _clientObservers.end())
		_clientObservers.erase(it);
}

void RDPClientController::connect()
{
	_tpktLayer->connect();
}

void RDPClientController::close()
{
    _pduLayer->close();
}

void RDPClientController::transportRecv(Buffer *data)
{
    _cssp->dataReceived(data);
}

bool RDPClientController::connectNla()
{
	RDPInfo &info = _secLayer->info();

	if (!_ssl)
		return false;
	if (!_ntlm->init(info.getDomain(), info.getUsername(), info.getPassword()))
		return false;
	return _cssp->connectNla(_ssl);
}

uint16_t RDPClientController::getColorDepth()
{
    return _pduLayer->serverCapabilitySets().bitmap.preferredBitsPerPixel;
}

bool RDPClientController::getKeyEventUnicodeSupport()
{
    return (_pduLayer->serverCapabilitySets().input.inputFlags & INPUT_FLAG_UNICODE) ? true : false;
}

void RDPClientController::setPerformanceSession()
{
    _secLayer->info().extendedInfo->performanceFlags =
        PERF_DISABLE_WALLPAPER | PERF_DISABLE_MENUANIMATIONS |
        PERF_DISABLE_CURSOR_SHADOW | PERF_DISABLE_THEMING |
        PERF_DISABLE_FULLWINDOWDRAG;
}

void RDPClientController::setScreen(uint16_t width, uint16_t height)
{
    _mcsLayer->getGCCClientSettings().core.desktopWidth = width;
    _mcsLayer->getGCCClientSettings().core.desktopHeight = height;
}

void RDPClientController::setUsername(const string &username)
{
	_secLayer->info().setUsername(username);
    _secLayer->licenceManager()->setUsername(username);
}

void RDPClientController::setPassword(const string &password)
{
    setAutologon();
    _secLayer->info().setPassword(password);
}

void RDPClientController::setDomain(const string &domain)
{
	_secLayer->info().setDomain(domain);
}

void RDPClientController::setAutologon()
{
    _secLayer->info().d.flag |= INFO_AUTOLOGON;
}

void RDPClientController::setAlternateShell(const string &appName)
{
    _secLayer->info().setAlternateShell(appName);
}

void RDPClientController::setKeyboardLayout(const string &layout)
{
    if (layout == "fr")
        _mcsLayer->getGCCClientSettings().core.kbdLayout = KBD_LAYOUT_FRENCH;
    else if (layout == "us")
        _mcsLayer->getGCCClientSettings().core.kbdLayout = KBD_LAYOUT_US;
}

void RDPClientController::setHostname(const string &hostname)
{
	_mcsLayer->getGCCClientSettings().core.setClientName(hostname);    
	_secLayer->licenceManager()->setHostname(hostname);
}

void RDPClientController::setSecurityLevel(int level)
{
    if (level == RDP_LEVEL_RDP)
        _x224Layer->setRequestedPtotocol(PROTOCOL_RDP);
    else if (level == RDP_LEVEL_SSL)
        _x224Layer->setRequestedPtotocol(PROTOCOL_SSL);
    else if (level == RDP_LEVEL_NLA)
        _x224Layer->setRequestedPtotocol(PROTOCOL_SSL | PROTOCOL_HYBRID);
}

void RDPClientController::sendPointerEvent(uint16_t x, uint16_t y, uint8_t button, bool isPressed)
{
    if (!_isReady)
        return;

    PointerEvent ev;

    if (isPressed)
        ev.pointerFlags |= PTRFLAGS_DOWN;

    if (button == 1)
        ev.pointerFlags |= PTRFLAGS_BUTTON1;
    else if (button == 2)
        ev.pointerFlags |= PTRFLAGS_BUTTON2;
    else if (button == 3)
        ev.pointerFlags |= PTRFLAGS_BUTTON3;
    else
        ev.pointerFlags |= PTRFLAGS_MOVE;

    // position
    ev.xPos = x;
    ev.yPos = y;

    // send proper event
    Buffer s;
    s.append(&ev, sizeof(ev));
    _pduLayer->sendInputEvents(INPUT_EVENT_MOUSE, 1, &s);
}

void RDPClientController::onUpdate(std::vector<BitmapDataPtr> &rectangles)
{
	RDPClientObserverList::iterator it;

	for (size_t i = 0; i < rectangles.size(); ++i) {
		BitmapDataPtr b = rectangles[i];
		for (it = _clientObservers.begin(); it != _clientObservers.end(); ++it) {
			(*it)->onUpdate(b->d.destLeft, b->d.destTop, b->d.destRight, b->d.destBottom,
				            b->d.width, b->d.height, b->d.bitsPerPixel,
							(b->flags & BITMAP_COMPRESSION) ? true : false, 
							b->bitmapDataStream);
		}
	}
}

void RDPClientController::onReady()
{
	RDPClientObserverList::iterator it;

    _isReady = true;
	for (it = _clientObservers.begin(); it != _clientObservers.end(); ++it)
		(*it)->onReady();
}

void RDPClientController::onSessionReady()
{
	RDPClientObserverList::iterator it;

    _isReady = true;
	for (it = _clientObservers.begin(); it != _clientObservers.end(); ++it)
		(*it)->onSessionReady();
}

void RDPClientController::onClose()
{
	RDPClientObserverList::iterator it;

    _isReady = false;
	for (it = _clientObservers.begin(); it != _clientObservers.end(); ++it)
		(*it)->onClose();
}

void RDPClientController::sendWheelEvent(uint16_t x, uint16_t y, uint8_t step,
                                         bool isNegative, bool isHorizontal)
{
    if (!_isReady)
        return;

    PointerEvent ev;

    if (isHorizontal)
        ev.pointerFlags |= PTRFLAGS_HWHEEL;
    else
        ev.pointerFlags |= PTRFLAGS_WHEEL;

    if (isNegative)
        ev.pointerFlags |= PTRFLAGS_WHEEL_NEGATIVE;

    ev.pointerFlags |= (step & WheelRotationMask);

    // position
    ev.xPos = x;
    ev.yPos = y;

    // send proper event
    Buffer s;
    s.append(&ev, sizeof(ev));
    _pduLayer->sendInputEvents(INPUT_EVENT_MOUSE, 1, &s);
}

void RDPClientController::sendKeyEventScancode(uint32_t code, bool isPressed, bool extended)
{
    if (!_isReady)
        return;

    ScancodeKeyEvent ev;
    ev.keycode = code;
    if (!isPressed)
        ev.keyboardFlags |= KBDFLAGS_RELEASE;
    if (extended)
        ev.keyboardFlags |= KBDFLAGS_EXTENDED;

    // send event
    Buffer s;
    s.append(&ev, sizeof(ev));
    _pduLayer->sendInputEvents(INPUT_EVENT_SCANCODE, 1, &s);
}

void RDPClientController::sendKeyEventUnicode(uint32_t code, bool isPressed)
{
    if (!_isReady)
        return;

    UnicodeKeyEvent ev;
    ev.unicode = code;
    if (!isPressed)
        ev.keyboardFlags |= KBDFLAGS_RELEASE;

    // send event
    Buffer s;
    s.append(&ev, sizeof(ev));
    _pduLayer->sendInputEvents(INPUT_EVENT_UNICODE, 1, &s);
}

void RDPClientController::sendRefreshOrder(uint16_t left, uint16_t top, uint16_t right, uint16_t bottom)
{
    RefreshRectPDU refreshPDU;
    InclusiveRectangle rect;

    rect.left = left;
    rect.top = top;
    rect.right = right;
    rect.bottom = bottom;

    refreshPDU.areasToRefresh.push_back(rect);

    Buffer pduData;
    refreshPDU.write(&pduData);
    _pduLayer->sendDataPDU(PDUTYPE2_REFRESH_RECT, &pduData);
}

//
// RDPServerController
//

RDPServerController::RDPServerController(uint8_t colorDepth, RdpTransport *rdpTransport)
    : _isReady(false)
{
    _pduLayer = new ServerPDULayer(this);
    _secLayer = new ServerSecLayer(_pduLayer, _pduLayer);
    _mcsLayer = new ServerMCSLayer(_secLayer);
    _x224Layer = new ServerX224Layer(_mcsLayer, rdpTransport);

    _tpktLayer = new TPKTLayer(_x224Layer, _secLayer, rdpTransport);

	_secLayer->init();
    setColorDepth(colorDepth);
}

RDPServerController::~RDPServerController()
{
    delete _pduLayer;
    delete _secLayer;
    delete _mcsLayer;
    delete _x224Layer;
    delete _tpktLayer;
}

void RDPServerController::addServerObserver(RDPServerObserver *observer)
{
	RDPServerObserverList::iterator it;

	it = std::find(_serverObservers.begin(), _serverObservers.end(), observer);
	if (it == _serverObservers.end())
		_serverObservers.push_back(observer);
}

void RDPServerController::removeServerObserver(RDPServerObserver *observer)
{
	RDPServerObserverList::iterator it;

	it = std::find(_serverObservers.begin(), _serverObservers.end(), observer);
	if (it == _serverObservers.end())
		_serverObservers.erase(it);
}

void RDPServerController::listen()
{
	_tpktLayer->connect();
}

void RDPServerController::close()
{
    _pduLayer->close();
}

void RDPServerController::transportRecv(Buffer *data)
{
    _tpktLayer->dataReceived(data);
}

string RDPServerController::getHostname()
{
    return _mcsLayer->getGCCClientSettings().core.getClientName();
}

string RDPServerController::getUsername()
{
	return _secLayer->info().getUsername();
}

string RDPServerController::getPassword()
{
    return _secLayer->info().getPassword();
}

string RDPServerController::getDomain()
{
    return _secLayer->info().getDomain();
}

uint16_t RDPServerController::getColorDepth()
{
    return _colorDepth;
}

void RDPServerController::getScreen(uint16_t &width, uint16_t &height)
{
    const BitmapCapability &bitmapCap = _pduLayer->clientCapabilitySets().bitmap;
    width = bitmapCap.desktopWidth;
    height = bitmapCap.desktopHeight;
}
void RDPServerController::setColorDepth(uint16_t colorDepth)
{
    _colorDepth = colorDepth;
    _pduLayer->serverCapabilitySets().bitmap.preferredBitsPerPixel = colorDepth;
    if (_isReady) {
        // restart connection sequence
        _isReady = false;

        DeactiveAllPDU msg;
        msg.shareId = _pduLayer->shareId();

        Buffer pduMessage;
        msg.write(&pduMessage);
        _pduLayer->sendPDU(PDUTYPE_DEACTIVATEALLPDU, &pduMessage);
    }
}

void RDPServerController::setKeyEventUnicodeSupport()
{
    _pduLayer->serverCapabilitySets().input.inputFlags |= INPUT_FLAG_UNICODE;
}

void RDPServerController::onReady()
{
	RDPServerObserverList::iterator it;

    _isReady = true;
	for (it = _serverObservers.begin(); it != _serverObservers.end(); ++it)
		(*it)->onReady();
}

void RDPServerController::onClose()
{
	RDPServerObserverList::iterator it;

    _isReady = false;
	for (it = _serverObservers.begin(); it != _serverObservers.end(); ++it)
		(*it)->onClose();
}

void RDPServerController::onSlowPathInput(uint16_t numEvents, Buffer *slowPathInputEvents)
{
	RDPServerObserverList::iterator it;
    Buffer *s = slowPathInputEvents;
    SlowPathInputEvent et;

    for (uint16_t i = 0; i < numEvents; ++i) {
        s->retrieve(&et, sizeof(et));

		if (et.messageType == INPUT_EVENT_SYNC) {
			SynchronizeEvent ev;
			s->retrieve(&ev, sizeof(ev));
		}
        // scan code
        else if (et.messageType == INPUT_EVENT_SCANCODE) {
            ScancodeKeyEvent ev;
            s->retrieve(&ev, sizeof(ev));
			for (it = _serverObservers.begin(); it != _serverObservers.end(); ++it) {
				(*it)->onKeyEventScancode(ev.keycode, !(ev.keyboardFlags & KBDFLAGS_RELEASE),
                                          (ev.keyboardFlags & KBDFLAGS_EXTENDED) ? true : false);
			}
        }
        // unicode
        else if (et.messageType == INPUT_EVENT_UNICODE) {
            UnicodeKeyEvent ev;
            s->retrieve(&ev, sizeof(ev));
			for (it = _serverObservers.begin(); it != _serverObservers.end(); ++it) {
				(*it)->onKeyEventUnicode(ev.unicode, !(ev.keyboardFlags & KBDFLAGS_RELEASE));
			}
        }
        // mouse event
        else if (et.messageType == INPUT_EVENT_MOUSE) {
            PointerEvent ev;
            s->retrieve(&ev, sizeof(ev));
            bool isPressed = (ev.pointerFlags & PTRFLAGS_DOWN) ? true : false;
            uint8_t button = 0;
            if (ev.pointerFlags & PTRFLAGS_BUTTON1)
                button = 1;
            else if (ev.pointerFlags & PTRFLAGS_BUTTON2)
                button = 2;
            else if (ev.pointerFlags & PTRFLAGS_BUTTON3)
                button = 3;
			for (it = _serverObservers.begin(); it != _serverObservers.end(); ++it) {
				(*it)->onPointerEvent(ev.xPos, ev.yPos, button, isPressed);
			}
        } else {
			RDPP_LOG(TAG, WARN) << "unimpl SlowPathInputEvent(time: " << et.eventTime << ", type: " << (void *)et.messageType << ")";
		}
    }
}

void RDPServerController::sendUpdate(uint16_t destLeft, uint16_t destTop,
                                     uint16_t destRight, uint16_t destBottom,
                                     uint16_t width, uint16_t height, uint16_t bitsPerPixel,
                                     bool isCompress, const string &data)
{
    if (!_isReady)
        return;

    BitmapDataPtr bitmapData(new BitmapData);
    bitmapData->d.destLeft = destLeft;
    bitmapData->d.destTop = destTop;
    bitmapData->d.destRight = destRight;
    bitmapData->d.destBottom = destBottom;
    bitmapData->d.width = width;
    bitmapData->d.height = height;
    bitmapData->d.bitsPerPixel = bitsPerPixel;
    bitmapData->bitmapDataStream = data;
    if (isCompress)
        bitmapData->flags = BITMAP_COMPRESSION;

    std::vector<BitmapDataPtr> bmpList(1, bitmapData);
    _pduLayer->sendBitmapUpdatePDU(bmpList);
}
