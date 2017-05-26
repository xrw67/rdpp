#ifndef _RDPP_MITM_PROXY_CLIENT_H_
#define _RDPP_MITM_PROXY_CLIENT_H_

#include <rdp/rdp.h>
#include <ace/Reactor.h>
#include <ace_ssl/SSL_Context.h>
#include <ace_ssl/SSL_SOCK_Stream.h>

namespace rdpp {

    class ProxyServer;

    class ProxyClient : public ACE_Event_Handler, public RdpTransport, public RDPClientObserver
    {
    public:
	    ProxyClient(ProxyServer *server, ACE_Reactor *reactor);
	    virtual ~ProxyClient();

		void setServer(ProxyServer *server)
		{ _server = server; }

		RDPClientController *controller()
		{ return _controller.get(); }
	    
		int open(const ACE_INET_Addr &serverAddr);
       
	    virtual ACE_HANDLE get_handle(void) const
		{ return _stream.get_handle(); }
	    
		virtual int handle_input(ACE_HANDLE fd);
	    virtual int handle_close(ACE_HANDLE fd, ACE_Reactor_Mask mask);

		virtual void transportSend(Buffer *data);
		virtual void transportClose();
		virtual bool startTls();
		virtual bool isTlsSupport();

        virtual void onReady();
        virtual void onSessionReady();
        virtual void onClose();
        virtual void onUpdate(uint16_t destLeft, uint16_t destTop, uint16_t destRight,
							  uint16_t destBottom, uint16_t width, uint16_t height,
							  uint16_t bitsPerPixel, bool isCompress, const string &data);
	
    private:
        bool _sslEnabled;
		ACE_Reactor *_reactor;
        ACE_SSL_Context _context;
        ACE_SSL_SOCK_Stream _stream;
	    Buffer _readBuffer;
        ProxyServer *_server;
	    shared_ptr<RDPClientController> _controller;
    };

} // namespace rdpp

#endif // _RDPP_MITM_PROXY_CLIENT_H_
