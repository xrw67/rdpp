/**
 * @summary: Security Service Provider Interface (Microsoft)
 */
#ifndef _RDP_RDP_NLA_SSPI_H_
#define _RDP_RDP_NLA_SSPI_H_

#include <core/config.h>
#include <core/buffer.h>

namespace rdpp {

    /// @summary: generic class for authentication Protocol(ex : ntlmv2, SPNEGO or kerberos)
    class IAuthenticationProtocol
    {
    public:
        /// @summary: Client first handshake message for authentication protocol
        virtual bool getNegotiateMessage(Buffer *data) = 0;

        // @summary: Client last handshake message
        virtual bool getAuthenticateMessage(Buffer *challengeRequest, Buffer *message) = 0;

        /// @summary: return encoded credentials accorded with authentication protocol nego
        /// @return: (domain, username, password)
        virtual void getEncodedCredentials(string &domain, string &usename, string &password) = 0;

		/// @summary: encrypt data with key exchange in Authentication protocol
        virtual bool GSS_WrapEx(Buffer *data) = 0;

        /// @summary: decrypt data with key exchange in Authentication protocol
        /// @param data: {str}
        virtual bool GSS_UnWrapEx(Buffer *data) = 0;
    };

} // namespace rdpp

#endif // _RDP_RDP_NLA_SSPI_H_
