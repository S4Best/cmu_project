//------------------------------------------------------------------------------------------------
// File: NetworkTLS.h
// Project: LG Exec Ed Program
// Versions:
// 1.0 April 2017 - initial version
// Provides the ability to send and recvive UDP Packets for both Window and linux platforms
//------------------------------------------------------------------------------------------------
#ifndef NetworkTCPH
#define NetworkTCPH
#pragma comment (lib, "Ws2_32.lib")
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <BaseTsd.h>
#include <timeapi.h>
#include <windows.h>

#include "openssl_hostname_validation.h"

typedef SSIZE_T ssize_t;
#define  CLOSE_SOCKET closesocket
#define  SOCKET_FD_TYPE SOCKET
#define  BAD_SOCKET_FD INVALID_SOCKET


enum {
	TCP_RECV_TIMEOUT = -2,
	TCP_RECV_ERROR = -1,
	TCP_RECV_PEER_DISCONNECTED = 0
};

//------------------------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------------------------

typedef struct
{
 SOCKET_FD_TYPE ListenFd;
} TTcpListenPort;

typedef struct
{
 SOCKET_FD_TYPE ConnectedFd;
 boolean isSsl;
 SSL* ssl;
 SSL_CTX* ctx;
} TTcpConnectedPort;

//------------------------------------------------------------------------------------------------
//  Function Prototypes 
//------------------------------------------------------------------------------------------------
TTcpListenPort *OpenTcpListenPort(short localport);
void CloseTcpListenPort(TTcpListenPort **TcpListenPort);
TTcpConnectedPort* AcceptTcpConnection(TTcpListenPort* TcpListenPort,
	struct sockaddr_in* cli_addr, socklen_t* clilen,
	const char* ca_pem, const char* cert_pem, const char* key_pem);
TTcpConnectedPort* OpenTcpConnection(const char* remotehostname, const char* remoteportno,
	const char* ca_pem, const char* cert_pem, const char* key_pem);
void CloseTcpConnectedPort(TTcpConnectedPort **TcpConnectedPort);
ssize_t ReadDataTcp(TTcpConnectedPort *TcpConnectedPort,unsigned char *data, size_t length);
ssize_t BytesAvailableTcp(TTcpConnectedPort* TcpConnectedPort);
ssize_t WriteDataTcp(TTcpConnectedPort *TcpConnectedPort,unsigned char *data, size_t length);
int setNonBlockingSock(TTcpConnectedPort* TcpConnectedPort);
//------------------------------------------------------------------------------------------------
//END of Include
//------------------------------------------------------------------------------------------------
#endif




