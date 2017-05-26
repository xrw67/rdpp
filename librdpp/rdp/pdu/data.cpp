#include <rdp/pdu/data.h>

#define TAG "DATA"

namespace rdpp {

    string errorMessage(uint32_t eno)
    {
        switch (eno) {
        case ERRINFO_RPC_INITIATED_DISCONNECT: return "The disconnection was initiated by an administrative tool on the server in another session.";
        case ERRINFO_RPC_INITIATED_LOGOFF: return "The disconnection was due to a forced logoff initiated by an administrative tool on the server in another session.";
        case ERRINFO_IDLE_TIMEOUT: return "The idle session limit timer on the server has elapsed.";
        case ERRINFO_LOGON_TIMEOUT: return "The active session limit timer on the server has elapsed.";
        case ERRINFO_DISCONNECTED_BY_OTHERCONNECTION: return "Another user connected to the server, forcing the disconnection of the current connection.";
        case ERRINFO_OUT_OF_MEMORY: return "The server ran out of available memory resources.";
        case ERRINFO_SERVER_DENIED_CONNECTION: return "The server denied the connection.";
        case ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES: return "The user cannot connect to the server due to insufficient access privileges.";
        case ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED: return "The server does not accept saved user credentials and requires that the user enter their credentials for each connection.";
        case ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER: return "The disconnection was initiated by an administrative tool on the server running in the user's session.";
        case ERRINFO_LOGOFF_BY_USER: return "The disconnection was initiated by the user logging off his or her session on the server.";
        case ERRINFO_LICENSE_INTERNAL: return "An internal error has occurred in the Terminal Services licensing component.";
        case ERRINFO_LICENSE_NO_LICENSE_SERVER: return "A Remote Desktop License Server ([MS-RDPELE] section 1.1) could not be found to provide a license.";
        case ERRINFO_LICENSE_NO_LICENSE: return "There are no Client Access Licenses ([MS-RDPELE] section 1.1) available for the target remote computer.";
        case ERRINFO_LICENSE_BAD_CLIENT_MSG: return "The remote computer received an invalid licensing message from the client.";
        case ERRINFO_LICENSE_HWID_DOESNT_MATCH_LICENSE: return "The Client Access License ([MS-RDPELE] section 1.1) stored by the client has been modified.";
        case ERRINFO_LICENSE_BAD_CLIENT_LICENSE: return "The Client Access License ([MS-RDPELE] section 1.1) stored by the client is in an invalid format";
        case ERRINFO_LICENSE_CANT_FINISH_PROTOCOL: return "Network problems have caused the licensing protocol ([MS-RDPELE] section 1.3.3) to be terminated.";
        case ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL: return "The client prematurely ended the licensing protocol ([MS-RDPELE] section 1.3.3).";
        case ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION: return "A licensing message ([MS-RDPELE] sections 2.2 and 5.1) was incorrectly encrypted.";
        case ERRINFO_LICENSE_CANT_UPGRADE_LICENSE: return "The Client Access License ([MS-RDPELE] section 1.1) stored by the client could not be upgraded or renewed.";
        case ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS: return "The remote computer is not licensed to accept remote connections.";
        case ERRINFO_CB_DESTINATION_NOT_FOUND: return "The target endpoint could not be found.";
        case ERRINFO_CB_LOADING_DESTINATION: return "The target endpoint to which the client is being redirected is disconnecting from the Connection Broker.";
        case ERRINFO_CB_REDIRECTING_TO_DESTINATION: return "An error occurred while the connection was being redirected to the target endpoint.";
        case ERRINFO_CB_SESSION_ONLINE_VM_WAKE: return "An error occurred while the target endpoint (a virtual machine) was being awakened.";
        case ERRINFO_CB_SESSION_ONLINE_VM_BOOT: return "An error occurred while the target endpoint (a virtual machine) was being started.";
        case ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS: return "The IP address of the target endpoint (a virtual machine) cannot be determined.";
        case ERRINFO_CB_DESTINATION_POOL_NOT_FREE: return "There are no available endpoints in the pool managed by the Connection Broker.";
        case ERRINFO_CB_CONNECTION_CANCELLED: return "Processing of the connection has been cancelled.";
        case ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS: return "The settings contained in the routingToken field of the X.224 Connection Request PDU (section 2.2.1.1) cannot be validated.";
        case ERRINFO_CB_SESSION_ONLINE_VM_BOOT_TIMEOUT: return "A time-out occurred while the target endpoint (a virtual machine) was being started.";
        case ERRINFO_CB_SESSION_ONLINE_VM_SESSMON_FAILED: return "A session monitoring error occurred while the target endpoint (a virtual machine) was being started.";
        case ERRINFO_UNKNOWNPDUTYPE2: return "Unknown pduType2 field in a received Share Data Header (section 2.2.8.1.1.1.2).";
        case ERRINFO_UNKNOWNPDUTYPE: return "Unknown pduType field in a received Share Control Header (section 2.2.8.1.1.1.1).";
        case ERRINFO_DATAPDUSEQUENCE: return "An out-of-sequence Slow-Path Data PDU (section 2.2.8.1.1.1.1) has been received.";
        case ERRINFO_CONTROLPDUSEQUENCE: return "An out-of-sequence Slow-Path Non-Data PDU (section 2.2.8.1.1.1.1) has been received.";
        case ERRINFO_INVALIDCONTROLPDUACTION: return "A Control PDU (sections 2.2.1.15 and 2.2.1.16) has been received with an invalid action field.";
        case ERRINFO_INVALIDINPUTPDUTYPE: return "A Slow-Path Input Event (section 2.2.8.1.1.3.1.1) has been received with an invalid messageType field OR A Fast-Path Input Event (section 2.2.8.1.2.2) has been received with an invalid eventCode field";
        case ERRINFO_INVALIDINPUTPDUMOUSE: return "A Slow-Path Mouse Event (section 2.2.8.1.1.3.1.1.3) or Extended Mouse Event (section 2.2.8.1.1.3.1.1.4) has been received with an invalid pointerFlags field OR A Fast-Path Mouse Event (section 2.2.8.1.2.2.3) or Fast-Path Extended Mouse Event (section 2.2.8.1.2.2.4) has been received with an invalid pointerFlags field.";
        case ERRINFO_INVALIDREFRESHRECTPDU: return "An invalid Refresh Rect PDU (section 2.2.11.2) has been received.";
        case ERRINFO_CREATEUSERDATAFAILED: return "The server failed to construct the GCC Conference Create Response user data (section 2.2.1.4).";
        case ERRINFO_CONNECTFAILED: return "Processing during the Channel Connection phase of the RDP Connection Sequence (see section 1.3.1.1 for an overview of the RDP Connection Sequence phases) has failed.";
        case ERRINFO_CONFIRMACTIVEWRONGSHAREID: return "A Confirm Active PDU (section 2.2.1.13.2) was received from the client with an invalid shareId field.";
        case ERRINFO_CONFIRMACTIVEWRONGORIGINATOR: return "A Confirm Active PDU (section 2.2.1.13.2) was received from the client with an invalid originatorId field.";
        case ERRINFO_PERSISTENTKEYPDUBADLENGTH: return "There is not enough data to process a Persistent Key List PDU (section 2.2.1.17).";
        case ERRINFO_PERSISTENTKEYPDUILLEGALFIRST: return "A Persistent Key List PDU (section 2.2.1.17) marked as PERSIST_PDU_FIRST (0x01) was received after the reception of a prior Persistent Key List PDU also marked as PERSIST_PDU_FIRST.";
        case ERRINFO_PERSISTENTKEYPDUTOOMANYTOTALKEYS: return "A Persistent Key List PDU (section 2.2.1.17) was received which specified a total number of bitmap cache entries larger than 262144.";
        case ERRINFO_PERSISTENTKEYPDUTOOMANYCACHEKEYS: return "A Persistent Key List PDU (section 2.2.1.17) was received which specified an invalid total number of keys for a bitmap cache (the number of entries that can be stored within each bitmap cache is specified in the Revision 1 or 2 Bitmap Cache Capability Set (section 2.2.7.1.4) that is sent from client to server).";
        case ERRINFO_INPUTPDUBADLENGTH: return "There is not enough data to process Input Event PDU Data (section 2.2.8.1.1.3.1) or a Fast-Path Input Event PDU (section 2.2.8.1.2).";
        case ERRINFO_BITMAPCACHEERRORPDUBADLENGTH: return "There is not enough data to process the shareDataHeader, NumInfoBlocks, Pad1, and Pad2 fields of the Bitmap Cache Error PDU Data ([MS-RDPEGDI] section 2.2.2.3.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT: return "The dataSignature field of the Fast-Path Input Event PDU (section 2.2.8.1.2) does not contain enough data OR The fipsInformation and dataSignature fields of the Fast-Path Input Event PDU (section 2.2.8.1.2) do not contain enough data.";
        case ERRINFO_VCHANNELDATATOOSHORT: return "There is not enough data in the Client Network Data (section 2.2.1.3.4) to read the virtual channel configuration data OR There is not enough data to read a complete Channel PDU Header (section 2.2.6.1.1).";
        case ERRINFO_SHAREDATATOOSHORT: return "There is not enough data to process Control PDU Data (section 2.2.1.15.1) OR There is not enough data to read a complete Share Control Header (section 2.2.8.1.1.1.1) OR There is not enough data to read a complete Share Data Header (section 2.2.8.1.1.1.2) of a Slow-Path Data PDU (section 2.2.8.1.1.1.1) OR There is not enough data to process Font List PDU Data (section 2.2.1.18.1).";
        case ERRINFO_BADSUPRESSOUTPUTPDU: return "There is not enough data to process Suppress Output PDU Data (section 2.2.11.3.1) OR The allowDisplayUpdates field of the Suppress Output PDU Data (section 2.2.11.3.1) is invalid.";
        case ERRINFO_CONFIRMACTIVEPDUTOOSHORT: return "There is not enough data to read the shareControlHeader, shareId, originatorId, lengthSourceDescriptor, and lengthCombinedCapabilities fields of the Confirm Active PDU Data (section 2.2.1.13.2.1) OR There is not enough data to read the sourceDescriptor, numberCapabilities, pad2Octets, and capabilitySets fields of the Confirm Active PDU Data (section 2.2.1.13.2.1).";
        case ERRINFO_CAPABILITYSETTOOSMALL: return "There is not enough data to read the capabilitySetType and the lengthCapability fields in a received Capability Set (section 2.2.1.13.1.1.1).";
        case ERRINFO_CAPABILITYSETTOOLARGE: return "A Capability Set (section 2.2.1.13.1.1.1) has been received with a lengthCapability field that contains a value greater than the total length of the data received.";
        case ERRINFO_NOCURSORCACHE: return "Both the colorPointerCacheSize and pointerCacheSize fields in the Pointer Capability Set (section 2.2.7.1.5) are set to zero OR The pointerCacheSize field in the Pointer Capability Set (section 2.2.7.1.5) is not present, and the colorPointerCacheSize field is set to zero.";
        case ERRINFO_BADCAPABILITIES: return "The capabilities received from the client in the Confirm Active PDU (section 2.2.1.13.2) were not accepted by the server.";
        case ERRINFO_VIRTUALCHANNELDECOMPRESSIONERR: return "An error occurred while using the bulk compressor (section 3.1.8 and [MS-RDPEGDI] section 3.1.8) to decompress a Virtual Channel PDU (section 2.2.6.1).";
        case ERRINFO_INVALIDVCCOMPRESSIONTYPE: return "An invalid bulk compression package was specified in the flags field of the Channel PDU Header (section 2.2.6.1.1).";
        case ERRINFO_INVALIDCHANNELID: return "An invalid MCS channel ID was specified in the mcsPdu field of the Virtual Channel PDU (section 2.2.6.1).";
        case ERRINFO_VCHANNELSTOOMANY: return "The client requested more than the maximum allowed 31 static virtual channels in the Client Network Data (section 2.2.1.3.4).";
        case ERRINFO_REMOTEAPPSNOTENABLED: return "The INFO_RAIL flag (0x00008000) MUST be set in the flags field of the Info Packet (section 2.2.1.11.1.1) as the session on the remote server can only host remote applications.";
        case ERRINFO_CACHECAPNOTSET: return "The client sent a Persistent Key List PDU (section 2.2.1.17) without including the prerequisite Revision 2 Bitmap Cache Capability Set (section 2.2.7.1.4.2) in the Confirm Active PDU (section 2.2.1.13.2).";
        case ERRINFO_BITMAPCACHEERRORPDUBADLENGTH2: return "The NumInfoBlocks field in the Bitmap Cache Error PDU Data is inconsistent with the amount of data in the Info field ([MS-RDPEGDI] section 2.2.2.3.1.1).";
        case ERRINFO_OFFSCRCACHEERRORPDUBADLENGTH: return "There is not enough data to process an Offscreen Bitmap Cache Error PDU ([MS-RDPEGDI] section 2.2.2.3.2).";
        case ERRINFO_GDIPLUSPDUBADLENGTH: return "There is not enough data to process a GDI+ Error PDU ([MS-RDPEGDI] section 2.2.2.3.4).";
        case ERRINFO_SECURITYDATATOOSHORT2: return "There is not enough data to read a Basic Security Header (section 2.2.8.1.1.2.1).";
        case ERRINFO_SECURITYDATATOOSHORT3: return "There is not enough data to read a Non-FIPS Security Header (section 2.2.8.1.1.2.2) or FIPS Security Header (section 2.2.8.1.1.2.3).";
        case ERRINFO_SECURITYDATATOOSHORT4: return "There is not enough data to read the basicSecurityHeader and length fields of the Security Exchange PDU Data (section 2.2.1.10.1).";
        case ERRINFO_SECURITYDATATOOSHORT5: return "There is not enough data to read the CodePage, flags, cbDomain, cbUserName, cbPassword, cbAlternateShell, cbWorkingDir, Domain, UserName, Password, AlternateShell, and WorkingDir fields in the Info Packet (section 2.2.1.11.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT6: return "There is not enough data to read the CodePage, flags, cbDomain, cbUserName, cbPassword, cbAlternateShell, and cbWorkingDir fields in the Info Packet (section 2.2.1.11.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT7: return "There is not enough data to read the clientAddressFamily and cbClientAddress fields in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT8: return "There is not enough data to read the clientAddress field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT9: return "There is not enough data to read the cbClientDir field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT10: return "There is not enough data to read the clientDir field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT11: return "There is not enough data to read the clientTimeZone field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT12: return "There is not enough data to read the clientSessionId field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT13: return "There is not enough data to read the performanceFlags field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT14: return "There is not enough data to read the cbAutoReconnectCookie field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT15: return "There is not enough data to read the autoReconnectCookie field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT16: return "The cbAutoReconnectCookie field in the Extended Info Packet (section 2.2.1.11.1.1.1) contains a value which is larger than the maximum allowed length of 128 bytes.";
        case ERRINFO_SECURITYDATATOOSHORT17: return "There is not enough data to read the clientAddressFamily and cbClientAddress fields in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT18: return "There is not enough data to read the clientAddress field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT19: return "There is not enough data to read the cbClientDir field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT20: return "There is not enough data to read the clientDir field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT21: return "There is not enough data to read the clientTimeZone field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT22: return "There is not enough data to read the clientSessionId field in the Extended Info Packet (section 2.2.1.11.1.1.1).";
        case ERRINFO_SECURITYDATATOOSHORT23: return "There is not enough data to read the Client Info PDU Data (section 2.2.1.11.1).";
        case ERRINFO_BADMONITORDATA: return "The monitorCount field in the Client Monitor Data (section 2.2.1.3.6) is invalid.";
        case ERRINFO_VCDECOMPRESSEDREASSEMBLEFAILED: return "The server-side decompression buffer is invalid, or the size of the decompressed VC data exceeds the chunking size specified in the Virtual Channel Capability Set (section 2.2.7.1.10).";
        case ERRINFO_VCDATATOOLONG: return "The size of a received Virtual Channel PDU (section 2.2.6.1) exceeds the chunking size specified in the Virtual Channel Capability Set (section 2.2.7.1.10).";
		case ERRINFO_DECRYPTFAILED: return "ERRINFO_DECRYPTFAILED";
		case ERRINFO_ENCRYPTFAILED: return "ERRINFO_ENCRYPTFAILED";
		case ERRINFO_ENCPKGMISMATCH: return "ERRINFO_ENCPKGMISMATCH";
		case ERRINFO_DECRYPTFAILED2: return "ERRINFO_DECRYPTFAILED2";
		}

        char buf[64];
        sprintf(buf, "Unknown code 0x%x", eno);
        return buf;
    }

} // namespace rdpp
