#include <rdp/lic.h>
#include <core/crypto.h>
#include <rdp/t125/gcc.h>

#define TAG "LIC"

namespace rdpp {

	/// @summary: A license packet
    struct LicPacket {
        uint8_t bMsgtype;
        uint8_t flag;
        uint16_t wMsgSize; // sizeof(this)

        LicPacket() : flag(PREAMBLE_VERSION_3_0) {}
    };

    void createValidClientLicensingErrorMessage(Buffer *s)
    {
        LicensingErrorMessage message;
        LicPacket licPacket;
		
		message.dwErrorCode = STATUS_VALID_CLIENT;
        message.dwStateTransition = ST_NO_TRANSITION;
		message.write(s);

		licPacket.bMsgtype = MSG_TYPE_ERROR_ALERT;
		licPacket.wMsgSize = sizeof(licPacket) + s->length();	
		s->prepend(&licPacket, sizeof(licPacket));
    }

} // namespace rdpp

using namespace rdpp;

LicenseManager::LicenseManager(SecLayer *transport)
    : _transport(transport)
{
}

bool LicenseManager::recv(Buffer *s)
{
    LicPacket licPacket;
	s->retrieve(&licPacket, sizeof(licPacket));

    // end of automata
    if (licPacket.bMsgtype == MSG_TYPE_ERROR_ALERT) {
        LicensingErrorMessage licensingMessage;
        licensingMessage.read(s);

        if (licensingMessage.dwErrorCode == STATUS_VALID_CLIENT &&
                licensingMessage.dwStateTransition == ST_NO_TRANSITION)
            return true;
    } else if (licPacket.bMsgtype == MSG_TYPE_LICENSE_REQUEST) {
        ServerLicenseRequest licensingMessage;
        licensingMessage.read(s);
        sendClientNewLicenseRequest(licensingMessage);
    } else if (licPacket.bMsgtype == MSG_TYPE_PLATFORM_CHALLENGE) {
        ServerPlatformChallenge licensingMessage;
        licensingMessage.read(s);
        sendClientChallengeResponse(licensingMessage);
        return false;
    } else if (licPacket.bMsgtype == MSG_TYPE_NEW_LICENSE) {
        return true; // yes get a new license
    }

    RDPP_LOG(TAG, ERROR) << "Not a valid license packet";
    return false;
}

void LicenseManager::sendLicensePacket(uint8_t type, Buffer *data)
{
	LicPacket licPacket;

	licPacket.bMsgtype = type;
	licPacket.wMsgSize = sizeof(licPacket) + data->length();
	data->prepend(&licPacket, sizeof(licPacket));

	_transport->sendFlagged(SEC_LICENSE_PKT, data);
}

void LicenseManager::sendClientNewLicenseRequest(ServerLicenseRequest &licenseRequest)
{
	Buffer messageS;
	ClientNewLicenseRequest message;
	ServerCertificate *serverCert;
	ServerCertificate tmpCert;
	uint8_t clientRandom[CLIENT_RANDOM_LENGTH];
	uint8_t serverRandom[SERVER_RANDOM_LENGTH];
	uint8_t preMasterSecret[PREMASTER_SECRET_LENGTH];
	uint8_t masterSecret[MASTER_SECRET_LENGTH];
	uint8_t sessionKeyBlob[SESSION_KEY_BLOB_LENGTH];

    // get server information
	memcpy(serverRandom, licenseRequest.serverRandom.data(), SERVER_RANDOM_LENGTH);
    if (_transport->getGCCServerSettings().security.serverCertLen > 0) {
        serverCert = &_transport->getGCCServerSettings().security.serverCertificate;
    } else {
        Buffer s(licenseRequest.serverCertificate.blobData);
        tmpCert.read(&s);
		serverCert = &tmpCert;
    }

    // generate crypto values
    Rsa::random(clientRandom, 32);
    Rsa::random(preMasterSecret, 48);

	if (!security_master_secret(preMasterSecret, clientRandom, serverRandom, masterSecret) ||
		!security_session_key_blob(masterSecret, clientRandom, serverRandom, sessionKeyBlob)) {
		return;
	}

	security_mac_salt_key(sessionKeyBlob, clientRandom, serverRandom, _macSaltKey);
	
	if (!security_licensing_encryption_key(sessionKeyBlob, clientRandom, serverRandom, _licensingEncryptionKey))
		return;

    // format message
    Buffer modulus, exponent;
    serverCert->getPublicKey(modulus, exponent);

	Buffer encryptedPremasterSecret(modulus.length());
    Rsa::public_encrypt(preMasterSecret,PREMASTER_SECRET_LENGTH,
                        modulus.length(), modulus.data(), exponent.data(), 
						(uint8_t *)encryptedPremasterSecret.beginWrite());
	encryptedPremasterSecret.hasWritten(modulus.length());

	message.clientRandom.assign(clientRandom, CLIENT_RANDOM_LENGTH);
	message.encryptedPreMasterSecret.append(encryptedPremasterSecret.data(), encryptedPremasterSecret.length());
	message.ClientMachineName.append(_hostname.c_str(), _hostname.length());
	message.ClientMachineName.append("\x00", 1);
    message.ClientUserName.append(_username.c_str(), _username.length());
	message.ClientUserName.append("\x00", 1);

	message.write(&messageS);
	sendLicensePacket(MSG_TYPE_NEW_LICENSE_REQUEST, &messageS);
}

void LicenseManager::sendClientChallengeResponse(ServerPlatformChallenge &platformChallenge)
{
	Rc4 rc4;
	Buffer buffer;
	uint8_t encryptedHardwareId[HWID_LENGTH];
    Buffer &serverEncryptedChallenge(platformChallenge.encryptedPlatformChallenge.blobData);

    // decrypt server challenge
    // it should be TEST word in unicode format
	if (!rc4.setup(_licensingEncryptionKey, LICENSING_ENCRYPTION_KEY_LENGTH))
		return;
	buffer.resize(serverEncryptedChallenge.length());
	if (!rc4.update(serverEncryptedChallenge.length(), serverEncryptedChallenge.data(), buffer.data()))
		return;

    if (memcmp(buffer.data(), "T\x00E\x00S\x00T\x00\x00\x00", buffer.length())) { // L"TEST"
        RDPP_LOG(TAG, ERROR) << "bad license server challenge";
        return;
    }

    // generate hwid
    Buffer hwid;
    hwid.appendUInt32(2);
    hwid.append(_hostname);
    hwid.append(_username);
    hwid.append(16, '\0');

	buffer.append(hwid.data(), HWID_LENGTH);

	if (!rc4.setup(_licensingEncryptionKey, LICENSING_ENCRYPTION_KEY_LENGTH))
		return;
	if (!rc4.update(HWID_LENGTH, hwid.data(), encryptedHardwareId))
		return;

    ClientPLatformChallengeResponse message;
    message.encryptedPlatformChallengeResponse.append(serverEncryptedChallenge.data(), serverEncryptedChallenge.length());
    message.encryptedHWID.append(encryptedHardwareId, HWID_LENGTH);

	if (!security_mac_data(_macSaltKey, buffer.data(), buffer.length(), message.MACData))
		return;

	buffer.clear();
	message.write(&buffer);
	sendLicensePacket(MSG_TYPE_PLATFORM_CHALLENGE_RESPONSE, &buffer);
}
