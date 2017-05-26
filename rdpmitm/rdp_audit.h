


bool startRdpAuditLister(const string &id, const string &destIp, uint16_t destPort, uint16_t listenPort,
	const string &username, const string &password, const string &domain,                      
	ACE_Reactor *reactor);

bool stopRdpAuditListener(const string &id);


class RdpAuditListener
{

private:
	id;
	destIp;
	destPort;
	listenerPort;
	ProxyAcceptor;
	std::map<string, RdpAuditSession>
};


bool mirrorRdpAuditSession

class RdpAuditSession
{

	clientIp;
	clientPort;

	RdpAuditListener *listener;

	sessionId;

	

	ProxyClient;
	ProxyServer;
};