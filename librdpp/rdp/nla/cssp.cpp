#include <rdp/nla/cssp.h>
#include <core/ber.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#define TAG "CSSP"

using namespace rdpp;

static int nla_sizeof_nego_token(int length)
{
    length = BER::sizeofOctetString(length);
    length += BER::sizeofContextualTag(length);
    return length;
}

static int nla_sizeof_nego_tokens(int length)
{
    length = nla_sizeof_nego_token(length);
    length += BER::sizeofSequenceTag(length);
    length += BER::sizeofSequenceTag(length);
    length += BER::sizeofContextualTag(length);
    return length;
}

static int nla_sizeof_pub_key_auth(int length)
{
    length = BER::sizeofOctetString(length);
    length += BER::sizeofContextualTag(length);
    return length;
}

static int nla_sizeof_auth_info(int length)
{
    length = BER::sizeofOctetString(length);
    length += BER::sizeofContextualTag(length);
    return length;
}

static int nla_sizeof_ts_request(int length)
{
    length += BER::sizeofInteger(2);
    length += BER::sizeofContextualTag(3);
    return length;
}

static int nla_sizeof_ts_password_creds(TSPasswordCreds *creds)
{
    int length = 0;
    length += BER::sizeofSequenceOctetString(creds->domainName.length());
    length += BER::sizeofSequenceOctetString(creds->userName.length());
    length += BER::sizeofSequenceOctetString(creds->password.length());
    return length;
}

static int nla_sizeof_ts_credentials(TSCredentials *creds)
{
    int size = 0;
    size += BER::sizeofInteger(1);
    size += BER::sizeofContextualTag(BER::sizeofInteger(1));
    size += BER::sizeofSequenceOctetString(BER::sizeofSequence(nla_sizeof_ts_password_creds(&(creds->credentials))));
    return size;
}

bool TSRequest::read(Buffer *s)
{
    int length;

    // TSRequest
    if (!BER::readSequenceTag(s, length))
		return false;
    if (!BER::readContextualTag(s, 0, length, true))
		return false;
    if (!BER::readInteger(s, version)) // [0] version
        return false;

    // [1] negoTokens(NegoData)
    if (BER::readContextualTag(s, 1, length, true)) {
        if (!BER::readSequenceTag(s, length)) /* SEQUENCE OF NegoDataItem */
			return false;
		if (!BER::readSequenceTag(s, length)) /* NegoDataItem */
			return false;
		if (!BER::readContextualTag(s, 0, length, true)) /* [0] negoToken */
			return false;
		if (!BER::readOctetStringTag(s, length)) /* OCTET STRING */
			return false;
		if ((int)s->length() < length)
            return false;
        s->retrieve(negoToken, length);
    }

    // [2] authInfo (OCTET STRING)
    if (BER::readContextualTag(s, 2, length, true)) {
        if (!BER::readOctetStringTag(s, length) || // OCTET STRING
				((int)s->length() < length)) {
            return false;
        }
        s->retrieve(authInfo, length);
    }

    // [3] pubKeyAuth (OCTET STRING)
    if (BER::readContextualTag(s, 3, length, true)) {
        if (!BER::readOctetStringTag(s, length) || // OCTET STRING
				((int)s->length() < length)) {
            return false;
        }
        s->retrieve(pubKeyAuth, length);
    }

    // [4] errorCode(INTEGER)
    if (version >= 3) {
        if (BER::readContextualTag(s, 4, length, true)) {
            if (!BER::readInteger(s, errorCode))
                return false;
        }
    }
    return true;
}

bool TSRequest::write(Buffer *s)
{
    int length;
    int ts_request_length;
    int nego_tokens_length = 0;
    int pub_key_auth_length = 0;
    int auth_info_length = 0;
    int error_code_context_length = 0;
    int error_code_length = 0;

    if (version < 3 || errorCode == 0) {
        nego_tokens_length = (negoToken.length() > 0) ? nla_sizeof_nego_tokens(negoToken.length()) : 0;
        pub_key_auth_length = (pubKeyAuth.length() > 0) ? nla_sizeof_pub_key_auth(pubKeyAuth.length()) : 0;
        auth_info_length = (authInfo.length() > 0) ? nla_sizeof_auth_info( authInfo.length()) : 0;
    } else {
        error_code_length = BER::sizeofInteger(errorCode);
        error_code_context_length = BER::sizeofContextualTag(error_code_length);
    }

    length = nego_tokens_length + pub_key_auth_length + auth_info_length + error_code_context_length + error_code_length;
    ts_request_length = nla_sizeof_ts_request(length);

    // TSRequest
    BER::writeSequenceTag(s, ts_request_length); // SEQUENCE
	// [0] version
    BER::writeContextualTag(s, 0, 3, true);
    BER::writeInteger(s, version); // INTEGER

    // [1] negoTokens (NegoData)
    if (nego_tokens_length > 0) {
        int _length = BER::writeContextualTag(s, 1, BER::sizeofSequence(BER::sizeofSequence(BER::sizeofSequenceOctetString(negoToken.length()))), true); // NegoData
        _length += BER::writeSequenceTag(s, BER::sizeofSequence(BER::sizeofSequenceOctetString(negoToken.length()))); // SEQUENCE OF NegoDataItem
        _length += BER::writeSequenceTag(s, BER::sizeofSequenceOctetString(negoToken.length())); // NegoDataItem
        _length += BER::writeSequenceOctetString(s, 0, negoToken.c_str(), negoToken.length()); // OCTET STRING
        if (_length != nego_tokens_length)
            return false;
    }

    // [2] authInfo (OCTET STRING)
    if (auth_info_length > 0) {
		if (BER::writeSequenceOctetString(s, 2, authInfo.c_str(), authInfo.length()) != auth_info_length)
            return false;
    }

    // [3] pubKeyAuth (OCTET STRING)
    if (pub_key_auth_length > 0) {
        if (BER::writeSequenceOctetString(s, 3, pubKeyAuth.c_str(), pubKeyAuth.length()) != pub_key_auth_length)
            return false;
    }

    // [4] errorCode (INTEGER)
    if (error_code_length > 0) {
        BER::writeContextualTag(s, 4, error_code_length, true);
        BER::writeInteger(s, errorCode);
    }
    return true;
}

int TSPasswordCreds::write(Buffer *s)
{
    int size = 0;
    int innerSize = nla_sizeof_ts_password_creds(this);

    // TSPasswordCreds (SEQUENCE)
    size += BER::writeSequenceTag(s, innerSize);
    // [0] domainName (OCTET STRING)
	size += BER::writeSequenceOctetString(s, 0, domainName.data(), domainName.length());
    // [1] userName (OCTET STRING)
    size += BER::writeSequenceOctetString(s, 1, userName.data(), userName.length());
    // [2] password (OCTET STRING)
    size += BER::writeSequenceOctetString(s, 2, password.data(), password.length());
    
    return size;
}

int TSCredentials::write(Buffer *s)
{
    int size = 0;
    int passwordSize;
    int innerSize = nla_sizeof_ts_credentials(this);

    // TSCredentials (SEQUENCE)
    size += BER::writeSequenceTag(s, innerSize);
    // [0] credType (INTEGER)
    size += BER::writeContextualTag(s, 0, BER::sizeofInteger(credType), true);
    size += BER::writeInteger(s, credType);
    // [1] credentials (OCTET STRING)
    passwordSize = BER::sizeofSequence(nla_sizeof_ts_password_creds(&credentials));
    size += BER::writeContextualTag(s, 1, BER::sizeofOctetString(passwordSize), true);
    size += BER::writeOctetStringTag(s, passwordSize);
    size += credentials.write(s);
    return size;
}

CSSP::CSSP(TPKTLayer* tpkt, Layer *presentation,
	       IAuthenticationProtocol *auth,
	       RdpTransport *rdpTransport)
    : _tpkt(tpkt)
	, _presentation(presentation)
    , _auth(auth)
	, _rdpTransport(rdpTransport)
	, _ssl(NULL)
    , _onRecvCallback(rdpp::bind(&TPKTLayer::dataReceived, tpkt, _1))
{
}

void CSSP::dataReceived(Buffer *data)
{
	RDPP_LOG(TAG, TRACE) << "CSSP::dataReceived, bytes: " << data->length();
	_onRecvCallback(data);
}

void CSSP::close()
{
	_rdpTransport->transportClose();
}

bool CSSP::connectNla(void *ssl)
{	
	Buffer s;
    TSRequest request;

    _auth->getNegotiateMessage(&request.negoToken);
    if (!request.write(&s)) {
		RDPP_LOG(TAG, ERROR) << "CSSP getNegotiateMessage failed";
		close();
		return false;
	}

	RDPP_LOG(TAG, TRACE) << "Send NTLMv2 negotiate message";
	_rdpTransport->transportSend(&s);

    // next state is receive a challenge
	_ssl = ssl;
    _onRecvCallback = rdpp::bind(&CSSP::recvChallenge, this, _1);
	return true;
}

void CSSP::recvChallenge(Buffer *data)
{
	Buffer s;
    TSRequest challenge;
	TSRequest pubkey;

	RDPP_LOG(TAG, TRACE) << "recv Challenge message";
	// send authenticate message with public key encoded

    if (!challenge.read(data)) {
        RDPP_LOG(TAG, ERROR) << "read DER TSRequest stream error";
        goto end;
    }
    
	if (!_auth->getAuthenticateMessage(&challenge.negoToken, &pubkey.negoToken))
		goto end;

    if (!getPublicKey(&pubkey.pubKeyAuth))
		goto end;

	_pubKeyBer = pubkey.pubKeyAuth;
    if (!_auth->GSS_WrapEx(&pubkey.pubKeyAuth)) // encrypted public key
		goto end;
	
	RDPP_LOG(TAG, TRACE) << "Public Key " << hexdump(_pubKeyBer);
	RDPP_LOG(TAG, TRACE) << "Encrypted Public Key " << hexdump(pubkey.pubKeyAuth);

    if (!pubkey.write(&s))
		goto end;

	_rdpTransport->transportSend(&s);
    // next step is received public key incremented by one
    _onRecvCallback = rdpp::bind(&CSSP::recvPubKeyInc, this, _1);
	return;
end:
	close();
}

void CSSP::recvPubKeyInc(Buffer *data)
{
	uint8_t *p1, *p2;
	Buffer s;
    TSRequest request;
    TSRequest credRequest;
    TSCredentials cred;

	RDPP_LOG(TAG, TRACE) << "recv PubKey Inc message";

    if (!request.read(data)) {
        RDPP_LOG(TAG, ERROR) << "read DER TSRequest stream error";
        goto end;
    }

	Buffer *pubKeyInc = &request.pubKeyAuth;
    if (!_auth->GSS_UnWrapEx(pubKeyInc))
		goto end;


    // check pubKeyInc = self._pubKeyBer + 1
	p1 = _pubKeyBer.data();
	p2 = pubKeyInc->data();

	p2[0]--;
	if (memcmp(p1, p2, pubKeyInc->length())) {
		RDPP_LOG(TAG, ERROR) << "Could not verify server's public key echo";
		goto end;
	}
	p2[0]++;

	// Send encrypted credentials
    _auth->getEncodedCredentials(cred.credentials.domainName, 
                                 cred.credentials.userName, 
								 cred.credentials.password);
    cred.write(&credRequest.authInfo);
    if (!_auth->GSS_WrapEx(&credRequest.authInfo))
		goto end;

    credRequest.write(&s);
	_rdpTransport->transportSend(&s);

    // reset state back to normal state
    _onRecvCallback = rdpp::bind(&TPKTLayer::dataReceived, _tpkt, _1);
    
    if (_presentation)
		_presentation->connect();

	return;
end:
	close();
}

bool CSSP::getPublicKey(Buffer *pubkey)
{
	uint8_t *p;
	int length;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	bool ret = false;

	if (!_ssl) {
		RDPP_LOG(TAG, ERROR) << "SSL is NULL";
		return false;
	}

	x509 = SSL_get_peer_certificate((SSL *)_ssl);
	if (!x509) {
		RDPP_LOG(TAG, ERROR) << "failed to get the server SSL certificate";
		goto end;
	}

	// TODO:: verify certificate

	pkey = X509_get_pubkey(x509);
	if (!pkey) {
		RDPP_LOG(TAG, ERROR) << "X509_get_pubkey() failed";
		goto end;
	}

	length = i2d_PublicKey(pkey, NULL);
	if (length < 1) {
		RDPP_LOG(TAG, ERROR) << "i2d_PublicKey() failed";
		goto end;
	}

	pubkey->ensureWritableBytes(length);
	p = pubkey->data();
	i2d_PublicKey(pkey, &p);
	pubkey->hasWritten(length);
	ret = true;
end:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);
	return ret;
}
