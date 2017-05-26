#include <rdp/nla/ntlm.h>
#include <core/buffer.h>
#include <core/log.h>
#include <core/string_util.h>
#include <core/unicode/utf.h>
#include <time.h>

#define TAG "NTLM"

using namespace rdpp;

static const char NTLM_CLIENT_SIGN_MAGIC[] = "session key to client-to-server signing key magic constant";
static const char NTLM_SERVER_SIGN_MAGIC[] = "session key to server-to-client signing key magic constant";
static const char NTLM_CLIENT_SEAL_MAGIC[] = "session key to client-to-server sealing key magic constant";
static const char NTLM_SERVER_SEAL_MAGIC[] = "session key to server-to-client sealing key magic constant";

/**
 * Get current time, in tenths of microseconds since midnight of January 1, 1601.
 * @param[out] timestamp 64-bit little-endian timestamp
 */
static void ntlm_current_time(uint8_t *timestamp)
{
	uint64_t time64;
	
	/* Timestamp (8 bytes), represented as the number of tenths of microseconds since midnight of January 1, 1601 */
	time64 = time(NULL) + 11644473600LL; /* Seconds since January 1, 1601 */
	time64 *= 10000000; /* Convert timestamp to tenths of a microsecond */
	memcpy(timestamp, &time64, 8);
}

static void KXKEYv2(const uint8_t *SessionBaseKey, Buffer *LmChallengeResponse,
	                const uint8_t *ServerChallenge, uint8_t *output)
{
    memcpy(output, SessionBaseKey, 16);
}

static bool SEALKEY(const uint8_t *ExportedSessionKey, bool client, uint8_t *output)
{
	bool ret;
	Digest md5;
		
	if (!md5.init("md5"))
		return false;
	if (!md5.update(ExportedSessionKey, 16))
		return false;

    if (client)
        ret = md5.update((uint8_t *)NTLM_CLIENT_SEAL_MAGIC, sizeof(NTLM_CLIENT_SEAL_MAGIC));
    else
        ret = md5.update((uint8_t *)NTLM_SERVER_SEAL_MAGIC, sizeof(NTLM_SERVER_SEAL_MAGIC));
	
	if (!ret)
		return false;

	return md5.final(output, Digest::MD5_DIGEST_LENGTH);
}

static bool SIGNKEY(const uint8_t *ExportedSessionKey, bool client, uint8_t *output)
{
	bool ret;
	Buffer blob;
	Digest md5;
		
	if (!md5.init("md5"))
		return false;
	if (!md5.update(ExportedSessionKey, 16))
		return false;

    if (client)
        ret = md5.update((uint8_t *)NTLM_CLIENT_SIGN_MAGIC, sizeof(NTLM_CLIENT_SIGN_MAGIC));
    else
        ret = md5.update((uint8_t *)NTLM_SERVER_SIGN_MAGIC, sizeof(NTLM_SERVER_SIGN_MAGIC));
	
	if (!ret)
		return false;

	return md5.final(output, Digest::MD5_DIGEST_LENGTH);
}

/**
 * Define NTOWFv2(Password, User, Domain) as
 * 	HMAC_MD5(MD4(UNICODE(Password)),
 * 		UNICODE(ConcatenationOf(UpperCase(User), Domain)))
 * EndDefine
 */
static bool NTOWFv2(const string &passwd, const string &user, 
	                const string &userDom, uint8_t *output)
{
	
	HMac hmac;
	uint8_t ntlm_hash[Digest::MD4_DIGEST_LENGTH];
	string pwd_unicode(utf::ascii_to_unicode(passwd));

	if (!Digest::digest("md4", (uint8_t *)pwd_unicode.data(), pwd_unicode.length(),
					    ntlm_hash, Digest::MD4_DIGEST_LENGTH))
		return false;

	string blob(utf::ascii_to_unicode(StringUtil::upper(user) + userDom));

	if (!hmac.init("md5", ntlm_hash, sizeof(ntlm_hash)))
		return false;
	if (!hmac.update((uint8_t *)blob.data(), blob.length()))
		return false;
	return hmac.final(output, Digest::MD5_DIGEST_LENGTH);
}

static bool LMOWFv2(const string &passwd, const string &user,
	                  const string &userDom, uint8_t *output)
{
    return NTOWFv2(passwd, user, userDom, output);
}

bool ComputeResponsev2(const uint8_t *responseKeyNT, 
                       const uint8_t *responseKeyLM,
                       const uint8_t *serverChallenge, 
                       const uint8_t *clientChallenge,
                       const uint8_t *timestamp, 
                       Buffer *serverName,
                       Buffer *NtChallengeResponse, 
                       Buffer *LmChallengeResponse,
                       uint8_t *SessionBaseKey)
{
	HMac hmac;
	Buffer temp;
    uint8_t nt_proof_str[16];

	// Construct temp
	temp.appendUInt8('\x01'); // RespType (1 byte)
	temp.appendUInt8('\x01'); // HighRespType (1 byte)
	temp.append(6, '\0'); // Reserved1 (2 bytes) & Reserved2 (4 bytes)
	temp.append(timestamp, 8); // Timestamp (8 bytes)
	temp.append(clientChallenge, 8); // ClientChallenge (8 bytes)
	temp.append(4, '\0'); // Reserved3 (4 bytes)
	temp.append(serverName);
	assert(temp.length() == serverName->length() + 28);

	// Concatenate server challenge with temp
	if (!hmac.init("md5", responseKeyNT, 16))
		return false;
	if (!hmac.update(serverChallenge, 8))
		return false;
	if (!hmac.update(temp.data(), temp.length()))
		return false;
	if (!hmac.final(nt_proof_str, 16))
		return false;

	// NtChallengeResponse, Concatenate NTProofStr with temp
	NtChallengeResponse->assign(nt_proof_str, 16);
    NtChallengeResponse->append(temp);

	// LmChallengeResponse
	uint8_t response[16];
	// Concatenate the server and client challenges, and HMAC-MD5
	if (!hmac.init("md5", responseKeyLM, 16))
		return false;
	if (!hmac.update(serverChallenge, 8))
		return false;
	if (!hmac.update(clientChallenge, 8))
		return false;
	if (!hmac.final(response, 16))
		return false;

	LmChallengeResponse->assign(response, 16);
	LmChallengeResponse->append(clientChallenge, 8);

	// Compute SessionBaseKey, the HMAC-MD5 hash of NTProofStr using the NTLMv2 hash as the key
	if (!hmac.init("md5", responseKeyLM, 16))
		return false;
	if (!hmac.update(nt_proof_str, 16))
		return false;
	if (!hmac.final(SessionBaseKey, 16))
		return false;
	return true;
}

static bool MAC(Rc4 &handle, const uint8_t *signingKey, uint32_t seqNum,
	            const Buffer &message, MessageSignatureEx &signature)
{
	HMac hmac;
	uint8_t hmac_digest[Digest::MD5_DIGEST_LENGTH];

	signature.SeqNum = seqNum;

	if (!hmac.init("md5", signingKey, Digest::MD5_DIGEST_LENGTH))
		return false;
	if (!hmac.update(&seqNum, sizeof(seqNum)))
		return false;
	if (!hmac.update(message.data(), message.length()))
		return false;
	if (!hmac.final(hmac_digest, sizeof(hmac_digest)))
		return false;

	return handle.update(8, hmac_digest, signature.Checksum);
}

/// @summary: Compute MIC signature
/// @param negotiateMessage: {NegotiateMessage}
/// @param challengeMessage : {ChallengeMessage}
/// @param authenticateMessage : {AuthenticateMessage}
/// @return: {str} signature
/// @see: https://msdn.microsoft.com/en-us/library/cc236676.aspx 
bool MIC(const uint8_t *exportedSessionKey, 
            Buffer &negotiateMessage, 
            Buffer &challengeMessage,
            Buffer &authenticateMessage,
			uint8_t *output)
{
	HMac hmac;
	
	if (!hmac.init("md5", exportedSessionKey, 16))
		return false;
	if (!hmac.update(negotiateMessage.data(), negotiateMessage.length()))
		return false;
	if (!hmac.update(challengeMessage.data(), challengeMessage.length()))
		return false;
	if (!hmac.update(authenticateMessage.data(), authenticateMessage.length()))
		return false;
	return hmac.final(output, 16);
}

NTLMv2::NTLMv2()
    : _enableUnicode(false)
{
}

bool NTLMv2::init(const string &domain, const string &user, const string &passwd)
{
	_domain = domain;
	_user = user;
	_password = passwd;
	
    if (!NTOWFv2(_password, _user, _domain, _responseKeyNT))
		return false;
	if (!LMOWFv2(_password, _user, _domain, _responseKeyLM))
		return false;
	return true;
}


bool NTLMv2::getNegotiateMessage(Buffer *s)
{
	NegotiateMessage message;
    message.h.NegotiateFlags = NTLMSSP_NEGOTIATE_KEY_EXCH |
                             NTLMSSP_NEGOTIATE_128 |
                             NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                             NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                             NTLMSSP_NEGOTIATE_NTLM |
                             NTLMSSP_NEGOTIATE_SEAL |
                             NTLMSSP_NEGOTIATE_SIGN |
                             NTLMSSP_REQUEST_TARGET |
                             NTLMSSP_NEGOTIATE_UNICODE;
	message.write(s);
	_negotiateMessage = *s;
	return true;
}

bool NTLMv2::getAuthenticateMessage(Buffer *challengeRequest, Buffer *message)
{
	Rc4 rc4;
	string domain, user;
	Buffer serverName;
	AvPairMap infos;
	bool computeMIC = false;
	uint8_t timestamp[8]; // uint64_t
	uint8_t clientChallenge[8];
	uint8_t serverChallenge[8];
	Buffer NtChallengeResponse;
	Buffer LmChallengeResponse;
	uint8_t SessionBaseKey[16];
	uint8_t KeyExchangeKey[16];
	uint8_t ExportedSessionKey[16];
	uint8_t EncryptedRandomSessionKey[16];
	uint8_t ClientSigningKey[16];
    uint8_t ServerSigningKey[16];
    uint8_t ClientSealingKey[16];
    uint8_t ServerSealingKey[16];

	_challengeMessage = *challengeRequest;

	ChallengeMessage challenge;
    challenge.read(challengeRequest);

	memcpy(serverChallenge, challenge.h.ServerChallenge, 8);
	if (!Rsa::random(clientChallenge, 8))
		return false;
	
	RDPP_LOG(TAG, TRACE) << "ServerChallenge " << hexdump(serverChallenge, 8);
	RDPP_LOG(TAG, TRACE) << "ClientChallenge " << hexdump(clientChallenge, 8);


    challenge.getTargetInfo(&serverName);
    challenge.getTargetInfoAsAvPairArray(infos);
    if (infos.find(MsvAvTimestamp) != infos.end()) {
        memcpy(&timestamp, infos[MsvAvTimestamp].data(), 8);
        computeMIC = true;
    } else {
        ntlm_current_time(timestamp);
    }

    if (!ComputeResponsev2(_responseKeyNT, _responseKeyLM, serverChallenge,
                      clientChallenge, timestamp, &serverName,
                      &NtChallengeResponse, &LmChallengeResponse, SessionBaseKey))
		return false;

    KXKEYv2(SessionBaseKey, &LmChallengeResponse, serverChallenge, KeyExchangeKey);
	RDPP_LOG(TAG, TRACE) << "KeyExchangeKey " << hexdump(KeyExchangeKey, 16);

	if (!Rsa::random(ExportedSessionKey, 16))
		return false;
	if (!rc4.setup(KeyExchangeKey, sizeof(KeyExchangeKey)))
		return false;
	if (!rc4.update(sizeof(ExportedSessionKey), ExportedSessionKey, EncryptedRandomSessionKey))
		return false;

	RDPP_LOG(TAG, TRACE) << "ExportedSessionKey " << hexdump(ExportedSessionKey, 16);
	RDPP_LOG(TAG, TRACE) << "EncryptedRandomSessionKey " << hexdump(EncryptedRandomSessionKey, 16);

    if (challenge.h.NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE) {
        _enableUnicode = true;
        domain = utf::ascii_to_unicode(_domain);
        user = utf::ascii_to_unicode(_user);
	} else {
		domain = _domain;
		user = _user;
	}

	AuthenticateMessage auth;
    auth.setup(challenge.h.NegotiateFlags, domain, user,
                NtChallengeResponse, LmChallengeResponse,
                EncryptedRandomSessionKey, "");

	auth.write(&_authenticateMessage);

    if (computeMIC) {
		if (!MIC(ExportedSessionKey, _negotiateMessage, _challengeMessage, _authenticateMessage, auth.MIC))
			return false;
    }

    if (!SIGNKEY(ExportedSessionKey, true, ClientSigningKey))
		return false;
    if (!SIGNKEY(ExportedSessionKey, false, ServerSigningKey))
		return false;
    if (!SEALKEY(ExportedSessionKey, true, ClientSealingKey))
		return false;
    if (!SEALKEY(ExportedSessionKey, false, ServerSealingKey))
		return false;

	RDPP_LOG(TAG, TRACE) << "ClientSigningKey " << hexdump(ClientSigningKey, 16);
	RDPP_LOG(TAG, TRACE) << "ServerSigningKey " << hexdump(ServerSigningKey, 16);
	RDPP_LOG(TAG, TRACE) << "ClientSealingKey " << hexdump(ClientSealingKey, 16);
	RDPP_LOG(TAG, TRACE) << "ServerSealingKey " << hexdump(ServerSealingKey, 16);

    auth.write(message);

	
	if (!_encryptHandle.setup(ClientSealingKey, 16)) {
		RDPP_LOG(TAG, ERROR) << "setup rc4 encrypt key failed";
		return false;
	}

	if (!_decryptHandle.setup(ServerSealingKey, 16)) {
		RDPP_LOG(TAG, ERROR) << "setup rc4 decrypt key failed";
		return false;
	}

	memcpy(_signingKey, ClientSigningKey, 16);
	memcpy(_verifyKey, ServerSigningKey, 16);
	_seqNum = 0;
	return true;
}   

void NTLMv2::getEncodedCredentials(string &domain, string &user, string &password)
{
    if (_enableUnicode) {
        domain = utf::ascii_to_unicode(_domain);
        user = utf::ascii_to_unicode(_user);
        password = utf::ascii_to_unicode(_password);
    } else {
        domain = _domain;
        user = _user;
        password = _password;
    }
}

bool NTLMv2::GSS_WrapEx(Buffer *data)
{
	MessageSignatureEx signature;
	Buffer plaintext(*data);

	// rc4 for encrypt first
	if (!_encryptHandle.update(data->length(), data->data(), data->data()))
		return false;
	// rc4 for signature second
	if (!MAC(_encryptHandle, _signingKey, _seqNum, plaintext, signature))
		return false;

	_seqNum += 1;
	data->prepend(&signature, sizeof(signature));
	return true;
}

bool NTLMv2::GSS_UnWrapEx(Buffer *data)
{
	HMac hmac;
	uint8_t verify[Digest::MD5_DIGEST_LENGTH]; // first 8 bytes
    MessageSignatureEx signature;

	data->retrieve(&signature, sizeof(signature));

	// decrypt message
	if (!_decryptHandle.update(data->length(), data->data(), data->data()))
		return false;
	if (!_decryptHandle.update(8, signature.Checksum, signature.Checksum))
		return false;

	// recompute checksum
	if (!hmac.init("md5", _verifyKey, 16))
		return false;
	if (!hmac.update(&signature.SeqNum, 4))
		return false;
	if (!hmac.update(data->data(), data->length()))
		return false;
	if (!hmac.final(verify, Digest::MD5_DIGEST_LENGTH))
		return false;

	if (memcmp(signature.Checksum, verify, 8) != 0) {
        RDPP_LOG(TAG, ERROR) << "NTLMv2SecurityInterface : Invalid checksum";
		return false;
	}
    return true;
}

