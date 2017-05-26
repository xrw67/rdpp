/**
 * @summary: Credential Security Support Provider (CredSSP)
 * @see: https://msdn.microsoft.com/en-us/library/cc226764.aspx
 *
 *
 *    Connecttion Sequence:
 *
 *       [client]                   [server]
 *								 
 *    1.send negotiate     ------>    
 *                         <------  2.send challenge
 *    3.send authenticate  ------> 
 *                         <------  4.send public key inc
 *    5.send credential    ------> 
 */

#ifndef _RDPP_RDP_NLA_CSSP_H_
#define _RDPP_RDP_NLA_CSSP_H_

#include <core/config.h>
#include <core/buffer.h>
#include <core/layer.h>
#include <rdp/nla/sspi.h>
#include <rdp/tpkt.h>

namespace rdpp {

    /// @summary: main structure
    /// @see: https://msdn.microsoft.com/en-us/library/cc226780.aspx
    struct TSRequest {
        uint32_t version;
        Buffer negoToken;
        Buffer authInfo;
        Buffer pubKeyAuth;
        uint32_t errorCode;

        TSRequest() : version(2), errorCode(0) {}
        bool read(Buffer *s);
        bool write(Buffer *s);
    };

	/// @summary: contain username and password
	/// @see: https://msdn.microsoft.com/en-us/library/cc226783.aspx
	///
	/// TSPasswordCreds ::= SEQUENCE {
	/// 	domainName  [0] OCTET STRING,
	/// 	userName    [1] OCTET STRING,
	/// 	password    [2] OCTET STRING
	/// }
	struct TSPasswordCreds {
        string domainName;
        string userName;
        string password;

        int write(Buffer *s);
    };

	/// @summary: contain user information
	/// @see: https://msdn.microsoft.com/en-us/library/cc226782.aspx
	/// TSCredentials ::= SEQUENCE {
	/// 	credType    [0] INTEGER,
	/// 	credentials [1] OCTET STRING
	/// }
    struct TSCredentials {
        uint32_t credType;
        TSPasswordCreds credentials;

        TSCredentials() : credType(1) {}
        int write(Buffer *s);
    };

    /// @summary: Handle CSSP connection
    /// Proxy class for authentication
    class CSSP
    {
    public:
        typedef function<void(Buffer *s)> OnRecvCallback;

        CSSP(TPKTLayer *tpkt, Layer *presentation, 
			 IAuthenticationProtocol *auth,
			 RdpTransport *rdpTransport);

		void close();

        /// @summary:  Inherit from twisted.protocol class
        /// main event of received data
        void dataReceived(Buffer *data);

        /// @summary: start NLA authentication
        bool connectNla(void *ssl);

        /// @summary: second state in cssp automata
        void recvChallenge(Buffer *data);

        /// @summary: the server send the pubKeyBer + 1
        void recvPubKeyInc(Buffer *data);

    private:
		RDPP_DISALLOW_EVIL_CONSTRUCTORS(CSSP);

		bool getPublicKey(Buffer *pubkey);

		RdpTransport *_rdpTransport;
        OnRecvCallback _onRecvCallback;

        TPKTLayer *_tpkt;
		Layer *_presentation;
        IAuthenticationProtocol *_auth;
		void *_ssl;
        Buffer _pubKeyBer;
    };

} // namespace rdpp

#endif // _RDPP_RDP_NLA_CSSP_H_
