#include "proxy_server.h"
#include "proxy_client.h"
#include <core/log.h>
#include <ace/Reactor.h>  
#include <ace/Time_Value.h>
#include <ace_ssl/SSL_SOCK_Acceptor.h>

#define TAG "PROXY.SERVER"

using namespace rdpp;

ProxyServer::ProxyServer(const string &ip, int port, const string &rssFile,
	                     const string &privateKeyFile, const string &certificateFile, 
                         int clientSecurity, ACE_Reactor *reactor)
	: _ip(ip)
	, _port(port)
	, _rss(rssFile)
    , _privateKeyFile(privateKeyFile)
	, _certificateFile(certificateFile)
	, _clientSecurityLevel(clientSecurity)
    , _client(NULL)
    , _stream(&_context)
    , _sslEnabled(false)
	, _reactor(reactor == NULL ? ACE_Reactor::instance() : reactor)
{
	_controller = rdpp::make_shared<RDPServerController>(16, this);
	_controller->addServerObserver(this);
	_controller->listen();
}

ProxyServer::~ProxyServer()
{
}

bool ProxyServer::open()
{
	RDPP_LOG(TAG, INFO) << "ProxyServer::open()";

	if (_reactor->register_handler(this, ACE_Event_Handler::READ_MASK) == -1) {
        RDPP_LOG(TAG, ERROR) << "Failed to register proxyServer";
        return false;
    }
	return true;
}

int ProxyServer::handle_input(ACE_HANDLE fd)
{
    ssize_t readBytes;
    ssize_t totalReadBytes = 0;

    while (1) {
        _readBuffer.ensureWritableBytes(8192);

        if (_sslEnabled)
            readBytes = _stream.recv(_readBuffer.beginWrite(), _readBuffer.writableBytes());
        else
            readBytes = _stream.peer().recv(_readBuffer.beginWrite(), _readBuffer.writableBytes());
        
        if (readBytes == 0) {
			RDPP_LOG(TAG, INFO) << " RDP Server Closed";
		} else if (readBytes == -1) {
			if (ACE_ERRNO_GET == EWOULDBLOCK) {
				RDPP_LOG(TAG, DEBUG) << "maybe tls re-negotiation";
				return 0;
			}

            RDPP_LOG(TAG, DEBUG) << "ProxyClient::handle_input( " << fd << "), read error = " << ACE_ERRNO_GET;
			handle_close(get_handle(), ACE_Event_Handler::ALL_EVENTS_MASK);
            return -1;
        }
    
        _readBuffer.hasWritten(readBytes);
        totalReadBytes += readBytes;

        if (_readBuffer.writableBytes() > 0) // Stream还有空闲，本次读完了
            break;
    }
    _controller->transportRecv(&_readBuffer);
	return 0;
}

int ProxyServer::handle_close(ACE_HANDLE fd, ACE_Reactor_Mask mask)
{
	RDPP_LOG(TAG, INFO) << "ProxyServer::handle_close, this=" << (void *)this;

	_controller->onClose();
	_reactor->remove_handler(this, ACE_Event_Handler::ALL_EVENTS_MASK | ACE_Event_Handler::DONT_CALL);
	
	if (_client)
		_client->setServer(NULL);
	
	delete this;
	return 0;
}

void ProxyServer::transportSend(Buffer *data)
{
    ssize_t sendBytes;

    while (data->length()) {
		if (_sslEnabled)
            sendBytes = _stream.send(data->data(), data->length());
        else
            sendBytes = _stream.peer().send(data->data(), data->length());

		if (sendBytes == 0) {
			RDPP_LOG(TAG, INFO) << "RDP Server Closed";
			return;
		} else if (sendBytes == -1) {
			if (ACE_ERRNO_GET == EWOULDBLOCK) {
				RDPP_LOG(TAG, DEBUG) << "maybe tls re-negotiation";
				return;
			}
            RDPP_LOG(TAG, ERROR) << "Send data error = " << ACE_ERRNO_GET;
			handle_close(get_handle(), ACE_Event_Handler::ALL_EVENTS_MASK);
            break;
        }
        data->retrieve(sendBytes);
    }
}

void ProxyServer::transportClose()
{
	RDPP_LOG(TAG, INFO) << "ProxyServer::transportClose";

	if (_sslEnabled) {
		_stream.close();
		_sslEnabled = false;
	} else {
		_stream.peer().close();
	}
}

bool ProxyServer::startTls()
{
    ACE_Time_Value timeout(3, 0);
    ACE_SSL_SOCK_Acceptor acceptor;

    _context.set_mode(ACE_SSL_Context::SSLv23_server);
    _context.set_options(SSL_OP_NO_SSLv2 | SSL_OP_TLS_BLOCK_PADDING_BUG | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

	if (_context.certificate(_certificateFile.c_str()) == -1) {
		RDPP_LOG(TAG, ERROR) << "load certificate file failed";
		return false;
	}

    if (_context.private_key(_privateKeyFile.c_str()) == -1) {
		RDPP_LOG(TAG, ERROR) << "load private key file failed";
		return false;
	}

    if (acceptor.ssl_accept(_stream, &timeout) != 0) {
        RDPP_LOG(TAG, ERROR) << "start TLS error";
        return false;
    }

    _sslEnabled = true;
	return true;
}

bool ProxyServer::isTlsSupport()
{
	return false;
	//return (!_privateKeyFile.empty() && !_certificateFile.empty());
}

void ProxyServer::onReady()
{
	RDPP_LOG(TAG, INFO) << "*RDP MSG*: onReady";

    if (!_client) {
		string domain(_controller->getDomain());
		string username(_controller->getUsername());
		string password(_controller->getPassword());

		_rss.credentials(username, password, domain, _controller->getHostname());

        uint16_t width, height;
        _controller->getScreen(width, height);
		_rss.screen(width, height, (uint8_t)_controller->getColorDepth());

        ProxyClient *c = new ProxyClient(this, _reactor);
        if (c->open(ACE_INET_Addr(_port, _ip.c_str())) == -1) {
            RDPP_LOG(TAG, ERROR) << "connect " << _ip << ":" << _port << "fail";
        }

		c->controller()->setScreen(width, height);
		c->controller()->setDomain(domain);
		c->controller()->setUsername(username);
		c->controller()->setPassword(password);
		c->controller()->setSecurityLevel(_clientSecurityLevel);
		c->controller()->setPerformanceSession();

		c->controller()->connect();
    }
}

void ProxyServer::onClose()
{
    RDPP_LOG(TAG, INFO) << "*RDP MSG*: onClose";

	_rss.close();
	
	if (!_client)
		return;
	_client->controller()->close();
}

void ProxyServer::onKeyEventScancode(uint32_t code, bool isPressed, bool isExtended)
{
	if (!_client)
		return;

    RDPP_LOG(TAG, TRACE) << "*RDP MSG*: onKeyEventScancode(code=" << (void *)code << ", " << "isPressed=" << isPressed << ", isExtended=" << isExtended << ")";
	_client->controller()->sendKeyEventScancode(code, isPressed, isExtended);
	_rss.keyScancode(code, isPressed);
}

void ProxyServer::onKeyEventUnicode(uint32_t code, bool isPressed)
{
	if (!_client)
		return;

    RDPP_LOG(TAG, TRACE) << "*RDP MSG*: onKeyEventUnicode(code=0x" << (void *)code << ", " << "isPressed" << isPressed << ")";
    _client->controller()->sendKeyEventUnicode(code, isPressed);
	_rss.keyUnicode(code, isPressed);
}

void ProxyServer::onPointerEvent(uint16_t x, uint16_t y, uint8_t button, bool isPressed)
{
	if (!_client)
		return;

    RDPP_LOG(TAG, TRACE) << "*RDP MSG*: onPointerEvent(x=" << x << ",y=" << y << ",button=" << button << ", isPressed=" << isPressed << ")";
    _client->controller()->sendPointerEvent(x, y, button, isPressed);
}
