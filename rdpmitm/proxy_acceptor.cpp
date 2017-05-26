#include "proxy_acceptor.h"
#include "proxy_client.h"
#include "proxy_server.h"
#include <core/log.h>
#include <core/string_util.h>
#include <time.h>

#define TAG "PROXY.ACCEPTOR"

using namespace rdpp;

ProxyAcceptor::ProxyAcceptor(const string &ip, int port, const string &ouputDirectory,
							 const string &privateKeyFilePath, const string &certificateFilePath,
							 int clientSecurity, ACE_Reactor *reactor)
    : _reactor(reactor == NULL ? ACE_Reactor::instance() : reactor)
	, _ip(ip)
	, _port(port)
    , _ouputDirectory(ouputDirectory)
	, _privateKeyFilePath(privateKeyFilePath)
	, _certificateFilePath(certificateFilePath)
	, _clientSecurity(clientSecurity)
	, _uniqueId(0)
{
}

ProxyAcceptor::~ProxyAcceptor()
{
}

int ProxyAcceptor::open(const ACE_INET_Addr &listenAddr)
{
    if (_acceptor.open(listenAddr, 1) == -1) {
        RDPP_LOG(TAG, ERROR) << "listening socket. errno = " << ACE_ERRNO_GET;
        return -1;
    }
    if (_reactor->register_handler(this, ACE_Event_Handler::ACCEPT_MASK) == -1) {
        RDPP_LOG(TAG, ERROR) << "Failed to register acceptor. errno = " << ACE_ERRNO_GET;
        return -1;
    }
	return 0;
}

int ProxyAcceptor::handle_input(ACE_HANDLE fd)
{
	char t_str[32] = {0};
	time_t seconds = time(NULL);
	tm *tm_time = localtime(&seconds);

	snprintf(t_str, sizeof(t_str), "%4d%02d%02d_%02d%02d%02d",
		tm_time->tm_year + 1900, tm_time->tm_mon + 1, tm_time->tm_mday,
		tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec);
	
	string rssFile(_ouputDirectory + "/" + StringUtil::format("%s_%s_%d_%u.rss", 
		t_str, _ip.c_str(), _port, ++_uniqueId));

	// ´´½¨ProxyServer
	ProxyServer *proxyServer;

    ACE_NEW_NORETURN(proxyServer, ProxyServer(_ip, _port, rssFile, _privateKeyFilePath, 
		                                      _certificateFilePath, _clientSecurity, _reactor));
    if (proxyServer == NULL) {
        RDPP_LOG(TAG, ERROR) << "Failed to allocate ProxyServer";
        return -1;
    }

    ACE_INET_Addr addr;
	if (_acceptor.net_accept(proxyServer->peer(), &addr) == -1) {
        RDPP_LOG(TAG, ERROR) << "Failed to accept proxyServer";
		delete proxyServer;
		return -1;
	}

	if (!proxyServer->open()) {
        RDPP_LOG(TAG, ERROR) << "Failed to open proxyServer";
        delete proxyServer;
        return -1;
    }

	RDPP_LOG(TAG, INFO) << "proxy acceptor request comming, fd=" << fd << ", pointer=" << (void *)proxyServer;
	return 0;
}

int ProxyAcceptor::handle_close(ACE_HANDLE, ACE_Reactor_Mask mask)
{
	_reactor->remove_handler(this, ACE_Event_Handler::ALL_EVENTS_MASK | ACE_Event_Handler::DONT_CALL);
	return 0;
}
