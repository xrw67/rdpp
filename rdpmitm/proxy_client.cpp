#include "proxy_client.h"
#include "proxy_server.h"
#include <core/log.h>
#include <ace/Reactor.h>  
#include <ace/Time_Value.h>
#include <ace_ssl/SSL_SOCK_Connector.h>

#define TAG "PROXY.CLIENT"

using namespace rdpp;

ProxyClient::ProxyClient(ProxyServer *server, ACE_Reactor *reactor)
    : _server(server)
    , _stream(&_context)
    , _sslEnabled(false)
	, _reactor(reactor)
{
	_controller = rdpp::make_shared<RDPClientController>(this);
	_controller->addClientObserver(this);
}

ProxyClient::~ProxyClient()
{
}

int ProxyClient::open(const ACE_INET_Addr &serverAddr)
{
	ACE_SSL_SOCK_Connector connector;
	ACE_Time_Value timeout(3, 0);

	if (connector.net_connect(_stream, serverAddr, &timeout) != 0)
		return -1;

	_reactor->register_handler(this, ACE_Event_Handler::READ_MASK);
	return 0;
}

int ProxyClient::handle_input(ACE_HANDLE fd)
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
			transportClose();
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

int ProxyClient::handle_close(ACE_HANDLE fd, ACE_Reactor_Mask mask)
{
	RDPP_LOG(TAG, INFO) << "ProxyClient::handle_close, this=" << (void *)this;

	_reactor->remove_handler(this, ACE_Event_Handler::ALL_EVENTS_MASK | ACE_Event_Handler::DONT_CALL);
	_controller->onClose();

	if (_server)
		_server->setClient(NULL);

	delete this;
	return 0;
}

void ProxyClient::transportSend(Buffer *data)
{
    ssize_t sendBytes;

    while (data->length() > 0) {
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
			transportClose();
            break;
        }
        data->retrieve(sendBytes);
    }
}

void ProxyClient::transportClose()
{
	RDPP_LOG(TAG, INFO) << "ProxyClient::transportClose";
	
	if (_sslEnabled) {
		_stream.close();
		_sslEnabled = false;
	} else {
		_stream.peer().close();
	}
}

bool ProxyClient::startTls()
{
    _context.set_mode(ACE_SSL_Context::TLSv1_client);
    _context.set_options(SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    _context.set_options(SSL_OP_TLS_BLOCK_PADDING_BUG);

    ACE_Time_Value timeout(3);
    ACE_SSL_SOCK_Connector connector;

    if (connector.ssl_connect(_stream, &timeout) != 0) {
        RDPP_LOG(TAG, ERROR) << "start TLS error";
        return false;
    }

	_controller->setSSL(_stream.ssl());
    _sslEnabled = true;
	return true;
}

bool ProxyClient::isTlsSupport()
{
	return true;
}

void ProxyClient::onReady()
{
    RDPP_LOG(TAG, INFO) << "*RDP MSG*: onReady";

    _server->setClient(this);
    // maybe color depth change
    _server->controller()->setColorDepth(_controller->getColorDepth());
}

void ProxyClient::onSessionReady()
{
    RDPP_LOG(TAG, INFO) << "*RDP MSG*: onSessionReady";
}

void ProxyClient::onClose()
{
    RDPP_LOG(TAG, INFO) << "*RDP MSG*: onClose";

	if (!_server)
		return;

	_server->rss()->close();
    _server->controller()->close();
}

void ProxyClient::onUpdate(uint16_t destLeft, uint16_t destTop, uint16_t destRight,
							  uint16_t destBottom, uint16_t width, uint16_t height,
							  uint16_t bitsPerPixel, bool isCompress, const string &data)
{
    RDPP_LOG(TAG, TRACE) << "*RDP MSG*: onUpdate()";

	_server->rss()->update(destLeft, destTop, destRight, destBottom,
                           width, height, bitsPerPixel, 
                           isCompress ? RSS_UPDATE_BMP : RSS_UPDATE_RAW,
						   data);

    _server->controller()->sendUpdate(destLeft, destTop, destRight, destBottom,
                           width, height, bitsPerPixel, isCompress, data);
}
