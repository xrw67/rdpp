#ifndef _RDPP_CORE_LAYER_H_
#define _RDPP_CORE_LAYER_H_

#include <core/config.h>
#include <core/buffer.h>

namespace rdpp {

	class RdpTransport
	{
	public:
		virtual void transportSend(Buffer *data) = 0;
		virtual void transportClose() = 0;
		virtual bool startTls() = 0;
		virtual bool isTlsSupport() = 0;

	};

	class NlaConnector
	{
	public:
		virtual bool connectNla() = 0;
	};

    /// @summary:  A simple double linked list with presentation and transport layer
    ///             and a subset of event(connect and close)
    class Layer
    {
    public:
        typedef function<void(Buffer *)> OnRecvCallback;

        /// @param presentation: presentation layer
        Layer(Layer *presentation = NULL)
            // presentation layer higher layer in model
            : _presentation(presentation)
            // transport layer under layer in model
            , _transport(NULL)
        {
            // auto set transport layer of own presentation layer
            if (_presentation != NULL)
                _presentation->_transport = this;
        }

	    /// @summary: Call when transport layer is connected
        ///           default is send connect event to presentation layer
	    virtual void connect()
	    {
		    if (_presentation != NULL)
			    _presentation->connect();
	    }
	
	    /// @summary: Close layer event, default is sent to transport layer
	    virtual void close()
	    {
		    if (_transport != NULL)
			    _transport->close();
	    }
        
        /// @summary: Signal that data is available
        /// @param s: Buffer
        virtual void recv(Buffer *data)
        {
            _onRecvCallback(data);
        }

        /// @summary: Send Buffer on layer
        /// @param data: Type or tuple element handle by transport layer
        virtual void send(Buffer *s) = 0;

        void setNextState(const OnRecvCallback &callback)
        {
			_onRecvCallback = callback;
        }

    protected:
	    Layer *_presentation; // ио╡Ц
	    Layer *_transport;  // об╡Ц

        OnRecvCallback _onRecvCallback;
    };

    class FastPathLayer
    {
    public:
        /// @summary: initialize stack
        FastPathLayer(FastPathLayer *fastPathListener = NULL)
        {
            _fastPathListener = fastPathListener;
            if (_fastPathListener != NULL)
                _fastPathListener->_fastPathSender = this;
        }

        /// @summary: Call when fast path packet is received
        virtual void recvFastPath(uint16_t secFlag, Buffer *data) = 0;

        /// @summary: Send fastPathS Type as fast path packet
        virtual void sendFastPath(uint16_t secFlag, Buffer *data) = 0;

    protected:
        FastPathLayer *_fastPathListener;
        FastPathLayer *_fastPathSender;
    };

} // namespace rdpp

#endif // _RDPP_CORE_LAYER_H_
