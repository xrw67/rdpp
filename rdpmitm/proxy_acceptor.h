#ifndef _RDPP_MITM_PROXY_ACCEPTOR_H_
#define _RDPP_MITM_PROXY_ACCEPTOR_H_

#include <core/config.h>
#include <ace/Reactor.h>
#include <ace_ssl/SSL_SOCK_Acceptor.h>

namespace rdpp {

class  ProxyAcceptor : public ACE_Event_Handler
{
public:
	ProxyAcceptor(const string &ip, int port,
		          const string &ouputDirectory,
				  const string &privateKeyFilePath,
				  const string &certificateFilePath,
				  int clientSecurity,
                  ACE_Reactor *reactor = NULL);

	virtual ~ProxyAcceptor();

	int open(const ACE_INET_Addr &listenAddr);

    // Overridden methods from the ACE_Event_Handler
    virtual ACE_HANDLE get_handle() const { return _acceptor.get_handle(); }

    //Create a read handler for the new connection and register that
    // handler with the reactor.
    virtual int handle_input(ACE_HANDLE);

    // Close the listening socket.
    virtual int handle_close(ACE_HANDLE, ACE_Reactor_Mask);

private:
	string _ip;
	int _port;
	ACE_Reactor *_reactor;
	ACE_SSL_SOCK_Acceptor _acceptor;
	string _ouputDirectory;
	string _privateKeyFilePath;
	string _certificateFilePath;
	int _clientSecurity;
	uint32_t _uniqueId;
};

} // namespace rdpp

#endif // _RDPP_MITM_PROXY_ACCEPTOR_H_
