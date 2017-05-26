// RDP proxy with Man in the middle capabilities
// Save RDP events in output RSR file format
// RSR file format can be read by rdpy - rsrplayer.py
//                ----------------------------
// Client RDP -> | ProxyServer | ProxyClient | ->Server RDP
//                ----------------------------
//                    | Record Session |
//                    ------------------

#include <core/log.h>
#include <rdp/rdp.h>
#include "proxy_acceptor.h"

#ifdef WIN32
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define TAG "RDPMITM"

using namespace rdpp;

static void makePath(string &dir)
{   
	char filePath[1000] = {0};
	bool bAbsolutePath = true;

#ifdef WIN32
	if (string::npos == dir.find(':'))
		bAbsolutePath = false;
#else
	if ('/' != dir[0])
		bAbsolutePath = false;
#endif
    
	if (!bAbsolutePath) {
		getcwd(filePath, sizeof(filePath));
		char cSeparator = filePath[strlen(filePath)];
		if (!(cSeparator == '/' || cSeparator == '\\'))
			strcat(filePath, "/");
        
		strncat(filePath, dir.c_str(), sizeof(filePath) - strlen(filePath));
	} else {
		strncpy(filePath, dir.c_str(), sizeof(filePath));
	}
    
	char *curDir = filePath;
    
	while (*curDir != '\0') {
		if (*curDir == '\\' || *curDir == '/') {
			*curDir = '\0';
#ifdef WIN32
		_mkdir(filePath);
#else
		mkdir(filePath, S_IRWXU);
#endif
			*curDir = '/';
		}
		++curDir;
	}
#ifdef WIN32
	_mkdir(filePath);
#else
	mkdir(filePath, S_IRWXU);
#endif 
	size_t pathLen = strlen(filePath);
	if ('/' != filePath[pathLen - 1]) {
		strcat(filePath, "/");
		++pathLen;
	}
    
	dir = filePath;

};

static void rdppLogCallback(const string &message)
{
	printf("%s\n", message.c_str());
}

static void help(const char *prog)
{
	printf("Usage: %s [option] target_ip:port\n", rdpp::detail::getFileNameFromPath(prog));
	printf("       [-l listen_port default 3389]\n");
    printf("       [-k private_key_file_path (mandatory for SSL)]\n");
    printf("       [-c certificate_file_path (mandatory for SSL)]\n");
    printf("       [-o output directory for recoded files]\n");
    printf("       [-r RDP standard security (XP or server 2003 client or older)]\n");
    printf("       [-n For NLA Client authentication (need to provide credentials)]\n");
    printf("Press any key to exit!\n");

	getchar();
}

int main(int argc, char **argv)
{
	string ouputDirectory; // 录像保存的文件夹
	string privateKeyFilePath;
	string certificateFilePath;
	int clientSecurity = RDP_LEVEL_SSL;
	int listen = 13389;

	bool badops = false;
	char *prog = argv[0];
	argc--;
	argv++;
	while (argc >= 1) {
		if (strcmp(*argv, "-h") == 0) {
			help(prog); return 0;
		} else if (strcmp(*argv, "-l") == 0) {
			if (--argc < 1) { help(prog); return 0; }
			 listen = atoi(*(++argv));
		} else if (strcmp(*argv, "-k") == 0) {
			if (--argc < 1) { help(prog); return 0; }
			privateKeyFilePath = *(++argv);
		} else if (strcmp(*argv, "-c") == 0) {
			if (--argc < 1) { help(prog); return 0; }
			certificateFilePath = *(++argv);
		} else if (strcmp(*argv, "-o") == 0) {
			if (--argc < 1) { help(prog); return 0; }
			ouputDirectory = *(++argv);
		} else if (strcmp(*argv, "-r") == 0) {
			clientSecurity = RDP_LEVEL_RDP;
		} else if (strcmp(*argv, "-n") == 0) {
			clientSecurity = RDP_LEVEL_NLA;
		} else {
			break;
		}
		argc--;
		argv++;
	}

	if (argc != 2) { // need ip port
		help(prog);
		return 0;
	}

	printf("********** Options **********\n");
	printf("output dir: %s\n", ouputDirectory.c_str());
	printf("private key file: %s\n", privateKeyFilePath.c_str());
	printf("certificate file: %s\n", certificateFilePath.c_str());
	printf("security: ");
	if (clientSecurity == RDP_LEVEL_RDP)
		printf("RDP\n");
	else if (clientSecurity == RDP_LEVEL_SSL)
		printf("SSL\n");
	else if (clientSecurity == RDP_LEVEL_NLA)
		printf("NLA\n");
	printf("listen: %d\n", listen);
	printf("target: %s:%d\n", argv[0], atoi(argv[1]));
	printf("****************************\n");

	rdpp::setLogLevel(NULL, rdpp::LOGLEVEL_INFO);
	rdpp::setLogHandler(rdpp::bind(rdppLogCallback, _1));

	makePath(ouputDirectory);

	ACE_Reactor *reactor = ACE_Reactor::instance();
	ProxyAcceptor acceptor(argv[0], atoi(argv[1]), ouputDirectory, privateKeyFilePath,
						   certificateFilePath, clientSecurity, reactor);
	
	if (acceptor.open(ACE_INET_Addr(listen)) == -1) {
		RDPP_LOG(TAG, ERROR) << "Listen port " << listen << " failed";
		return 0;
	}

	RDPP_LOG(TAG, INFO) << "ServerFactory Listen " << listen << " Successed";
	RDPP_LOG(TAG, INFO) << "event loop running...";
	reactor->run_reactor_event_loop();
	RDPP_LOG(TAG, INFO) << "rdp-mitm quit!";
	return 0;
}
