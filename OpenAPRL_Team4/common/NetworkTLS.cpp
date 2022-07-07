//------------------------------------------------------------------------------------------------
// File: NetworkTLS.cpp
// Provides the ability to send and recvive TCP byte streams for both Window and linux platforms
//------------------------------------------------------------------------------------------------
#include <iostream>
#include <new>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "NetworkTLS.h"
#include "sechelper.h"

#define  CLOSE_SOCKET closesocket
#define  SOCKET_FD_TYPE SOCKET
#define  BAD_SOCKET_FD INVALID_SOCKET

#define TARGET_SERVER "plate.server"
#define TARGET_CLIENT "plate.client"

//-----------------------------------------------------------------
// OpenTCPListenPort - Creates a Listen TCP port to accept
// connection requests
//-----------------------------------------------------------------
TTcpListenPort* OpenTcpListenPort(short localport)
{
	TTcpListenPort* TcpListenPort;
	struct sockaddr_in myaddr;

    TcpListenPort= new (std::nothrow) TTcpListenPort;  
  
    if (TcpListenPort==NULL)
    {
        fprintf(stderr, "TUdpPort memory allocation failed\n");
        return(NULL);
    }
    TcpListenPort->ListenFd=BAD_SOCKET_FD;

    WSADATA wsaData;
    int     iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) 
    {
        delete TcpListenPort;
        printf("WSAStartup failed: %d\n", iResult);
        return(NULL);
    }

	// create a socket
	if ((TcpListenPort->ListenFd = socket(AF_INET, SOCK_STREAM, 0)) == BAD_SOCKET_FD)
	{
		CloseTcpListenPort(&TcpListenPort);
		perror("socket failed\n");
		return(NULL);
	}
	int option = 1;

	if (setsockopt(TcpListenPort->ListenFd, SOL_SOCKET, SO_REUSEADDR, (char*)&option, sizeof(option)) < 0)
	{
		CloseTcpListenPort(&TcpListenPort);
		perror("setsockopt failed\n");
		return(NULL);
	}

	// bind it to all local addresses and pick any port number
	memset((char*)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(localport);

	if (bind(TcpListenPort->ListenFd, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0)
	{
		CloseTcpListenPort(&TcpListenPort);
		perror("bind failed\n");
		return(NULL);
	}


	if (listen(TcpListenPort->ListenFd, 5) < 0)
	{
		CloseTcpListenPort(&TcpListenPort);
		perror("bind failed\n");
		return(NULL);
	}
	return(TcpListenPort);
}
//-----------------------------------------------------------------
// END OpenTCPListenPort
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// CloseTcpListenPort - Closes the specified TCP listen port
//-----------------------------------------------------------------
void CloseTcpListenPort(TTcpListenPort** TcpListenPort)
{
	if ((*TcpListenPort) == NULL) return;
	if ((*TcpListenPort)->ListenFd != BAD_SOCKET_FD)
	{
		CLOSE_SOCKET((*TcpListenPort)->ListenFd);
		(*TcpListenPort)->ListenFd = BAD_SOCKET_FD;
	}
	delete (*TcpListenPort);
	(*TcpListenPort) = NULL;
	WSACleanup();
}
//-----------------------------------------------------------------
// END CloseTcpListenPort
//-----------------------------------------------------------------

static SSL_CTX* get_server_context(const char* ca_pem,
	const char* cert_pem,
	const char* key_pem) {
	SSL_CTX* ctx = NULL;
	unsigned char* pkey = NULL;
	size_t pkey_size = 0;
	std::vector<uint8_t> priv;
	std::vector<uint8_t> masterkey;
	Blob mBlob;
	std::vector<uint8_t>::iterator valueBytes;
	std::string str;
	int result=0, rawLength=0;

	/* Get a default context */
	if (!(ctx = SSL_CTX_new(TLS_server_method()))) {
		printf("SSL_CTX_new failed");
		return NULL;
	}

	/* Set the CA file location for the server */
	if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1) {
		printf("Could not set the CA file location\n");
		goto fail;
	}

	/* Load the client's CA file location as well */
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_pem));

	/* Set the server's certificate signed by the CA */
	if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1) {
		printf("Could not set the server's certificate\n");
		goto fail;
	}


	std::fill(priv.begin(), priv.end(), 0);
	std::fill(masterkey.begin(), masterkey.end(), 0);
	memset(&mBlob, 0, sizeof(Blob));

	result = loadMasterBlob(masterkey_path, &mBlob);
	if (result < 0)
	{
		printf("failed to load masterkey\n");
		goto fail;
	}

	rawLength = mBlob.length;
	masterkey.resize(rawLength);
	valueBytes = masterkey.begin();
	for (int i = 0; i < rawLength; i++) {
		valueBytes[i] = mBlob.value[i];
	}

	result = decryptDatatoBuffer(EncServerKeyFile, masterkey, priv);
	if (result < 1) {
		printf("failed to decrypt private key : %d\n", (int)result);
		goto fail;
	}

	str.assign(priv.begin(), priv.end());
	std::fill(priv.begin(), priv.end(), 0);
	priv = HexStringToByteArray(str);
	if (priv.size() < 0)
	{
		printf("hexstring to bytearray failed\n");
		goto fail;
	}

	/* Set the server's key for the above certificate */
	pkey = (unsigned char *)malloc(priv.size());
	if (pkey == NULL)
	{
		printf("failed to alloc memory\n");
		goto fail;
	}
	memcpy(pkey, &priv[0], priv.size());

	if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, pkey, priv.size()) != 1) {
		printf("Could not set the server's key\n");
		goto fail;
	}

	/* We've loaded both certificate and the key, check if they match */
	if (SSL_CTX_check_private_key(ctx) != 1) {
		printf("Server's certificate and the key don't match\n");
		goto fail;
	}

	/* We won't handle incomplete read/writes due to renegotiation */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	/* Specify that we need to verify the client as well */
	SSL_CTX_set_verify(ctx,
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		NULL);

	/* We accept only certificates signed only by the CA himself */
	SSL_CTX_set_verify_depth(ctx, 1);

	std::fill(priv.begin(), priv.end(), 0);
	std::fill(masterkey.begin(), masterkey.end(), 0);

	/* Done, return the context */
	free(pkey);
	return ctx;

fail:
	std::fill(priv.begin(), priv.end(), 0);
	std::fill(masterkey.begin(), masterkey.end(), 0);
	free(pkey);
	SSL_CTX_free(ctx);
	return NULL;
}

static const char* get_ssl_version_str(const SSL* s)
{
	if (s != NULL) {
		int ver = -1;
		ver = SSL_version(s);
		switch (ver) {
		case TLS1_3_VERSION:
			return "TLS1_3_VERSION";
		case TLS1_2_VERSION:
			return "TLS1_2_VERSION";
		case TLS1_1_VERSION:
			return "TLS1_1_VERSION";
		case TLS1_VERSION:
			return "TLS1_VERSION";
		case SSL3_VERSION:
			return "SSL3_VERSION";
		default:
			return "unknown";
		}
	}
	return "unknown";
}

//-----------------------------------------------------------------
// AcceptTcpConnection -Accepts a TCP Connection request from a
// Listening port
//-----------------------------------------------------------------
TTcpConnectedPort* AcceptTcpConnection(TTcpListenPort* TcpListenPort,
	struct sockaddr_in* cli_addr, socklen_t* clilen,
	const char* ca_pem, const char* cert_pem, const char* key_pem)
{
	TTcpConnectedPort* TcpConnectedPort;
	boolean isSsl = false;
	int rc = -1;
	X509* client_cert = NULL;
	char clientIP[20] = { 0, };

	printf("Server AcceptTcpConnection started\n");
	TcpConnectedPort = new (std::nothrow) TTcpConnectedPort;

	if (TcpConnectedPort == NULL)
	{
		printf("TUdpPort memory allocation failed\n");
		return(NULL);
	}

	/* initialization of TcpConnectedPort dynamiclly allocated */
	TcpConnectedPort->ConnectedFd = BAD_SOCKET_FD;
	TcpConnectedPort->isSsl = FALSE;
	TcpConnectedPort->ssl = NULL;
	TcpConnectedPort->ctx = NULL;

    if (ca_pem != NULL && cert_pem != NULL && key_pem != NULL) {
		isSsl = true;
	}
	
	if (isSsl) {
		/* Initialize OpenSSL */
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();

		/* Get a server context for our use */
		if (!(TcpConnectedPort->ctx = get_server_context(ca_pem, cert_pem, key_pem))) {
			printf("get_server_context failed\n");
			return(NULL);
		}
	}

	TcpConnectedPort->ConnectedFd = accept(TcpListenPort->ListenFd,
		(struct sockaddr*)cli_addr, clilen);

	if (TcpConnectedPort->ConnectedFd == BAD_SOCKET_FD)
	{
		printf("ERROR on accept\n");
		delete (TcpConnectedPort);
		return NULL;
	}

	int bufsize = 200 * 1024;
	if (setsockopt(TcpConnectedPort->ConnectedFd, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize)) == -1)
	{
		CloseTcpConnectedPort(&TcpConnectedPort);
		printf("setsockopt SO_SNDBUF failed\n");
		return(NULL);
	}

	if (setsockopt(TcpConnectedPort->ConnectedFd, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize)) == -1)
	{
		CloseTcpConnectedPort(&TcpConnectedPort);
		printf("setsockopt SO_SNDBUF failed\n");
		return(NULL);
	}

	int option = 1;
	if (setsockopt(TcpConnectedPort->ConnectedFd, IPPROTO_TCP, TCP_NODELAY, (char*)&option, sizeof(option)) < 0)
	{
		CloseTcpConnectedPort(&TcpConnectedPort);
		printf("setsockopt failed\n");
		return(NULL);
	}
		
	if (isSsl) {
		/* Get an SSL handle from the context */
		if (!(TcpConnectedPort->ssl = SSL_new(TcpConnectedPort->ctx))) {
			printf("Could not get an SSL handle from the context\n");
			goto ssl_exit;
		}

		/* Associate the newly accepted connection with this handle */
		SSL_set_fd(TcpConnectedPort->ssl, TcpConnectedPort->ConnectedFd);

		/* Now perform handshake */
		if ((rc = SSL_accept(TcpConnectedPort->ssl)) != 1) {
			printf("Could not perform SSL handshake\n");
			if (rc != 0) {
				SSL_shutdown(TcpConnectedPort->ssl);
			}
			SSL_free(TcpConnectedPort->ssl);
			goto ssl_exit;
		}

		/* Host name Verification is required!!!*/
		// Recover the client's certificate
		client_cert = SSL_get_peer_certificate(TcpConnectedPort->ssl);
		if (client_cert == NULL) {
			// The handshake was successful although the server did not provide a certificate
			// Most likely using an insecure anonymous cipher suite... get out!
			printf("SSL_get_peer_certificate failed\n");
			goto ssl_exit;
		}

		// Validate the hostname
		if (validate_hostname(TARGET_CLIENT, client_cert) != MatchFound) {
			printf("Hostname validation failed\n");
			goto error_verify_hostname;
		}

		/* Print success connection message on the server */
		char clientIP[20] = { 0, };
		if (inet_ntop(AF_INET, &cli_addr->sin_addr, clientIP, sizeof(clientIP)) == NULL) {
			printf("error inet_top\n");
			goto error_verify_hostname;
		}

		printf("SSL handshake successful with %s:%d, %s\n",
			clientIP, ntohs(cli_addr->sin_port), get_ssl_version_str(TcpConnectedPort->ssl));

	}

	TcpConnectedPort->isSsl = isSsl;

	return TcpConnectedPort;

error_verify_hostname:
	if (client_cert) {
		X509_free(client_cert);
	}
ssl_exit:
	if (isSsl) {
		SSL_CTX_free(TcpConnectedPort->ctx);
	}
	return NULL;
}
//-----------------------------------------------------------------
// END AcceptTcpConnection
//-----------------------------------------------------------------

static SSL_CTX* get_client_context(const char* ca_pem,
	const char* cert_pem,
	const char* key_pem) {
	SSL_CTX* ctx = NULL;
	unsigned char* pkey = NULL;
	size_t pkey_size = 0;
	std::string str;
	std::vector<uint8_t> priv;
	std::vector<uint8_t> masterkey;
	Blob mBlob;
	std::vector<uint8_t>::iterator valueBytes;
	int result = 0, rawLength = 0;

	/* Create a generic context */
	if (!(ctx = SSL_CTX_new(TLS_client_method()))) {
		printf("Cannot create a client context\n");
		return NULL;
	}

	/* Load the client's CA file location */
	if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1) {
		printf("Cannot load client's CA file\n");
		goto fail;
	}

	/* Load the client's certificate */
	if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1) {
		printf("Cannot load client's certificate file\n");
		goto fail;
	}

	std::fill(priv.begin(), priv.end(), 0);
	std::fill(masterkey.begin(), masterkey.end(), 0);
	memset(&mBlob, 0, sizeof(Blob));

	result = loadMasterBlob(masterkey_path, &mBlob);
	if (result < 1)
	{
		printf("failed to load masterkey\n");
		goto fail;
	}

	rawLength = mBlob.length;
	masterkey.resize(rawLength);
	valueBytes = masterkey.begin();
	for (int i = 0; i < rawLength; i++) {
		valueBytes[i] = mBlob.value[i];
	}

	result = decryptDatatoBuffer(EncClientKeyFile, masterkey, priv);
	if (result != 1) {
		printf("failed to decrypt private key : %d\n", (int)result);
		goto fail;
	}

	str.assign(priv.begin(), priv.end());
	std::fill(priv.begin(), priv.end(), 0);
	priv = HexStringToByteArray(str);
	if (priv.size() < 0)
	{
		printf("hexstring to bytearray failed\n");
		goto fail;
	}

	/* Set the server's key for the above certificate */
	pkey = (unsigned char*)malloc(priv.size());
	if (pkey == NULL)
	{
		printf("failed to alloc memory\n");
		goto fail;
	}
	memcpy(pkey, &priv[0], priv.size());

	/* Set the client's key for the above certificate */
	if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, priv.data(), priv.size()) != 1) {
		printf("Could not set the server's key\n");
		goto fail;
	}
	std::fill(priv.begin(), priv.end(), 0);
	
	printf("success to free to pkey\n");
	/* Verify that the client's certificate and the key match */
	if (SSL_CTX_check_private_key(ctx) != 1) {
		printf("Client's certificate and key don't match\n");
		goto fail;
	}

	/* We won't handle incomplete read/writes due to renegotiation */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	/* Specify that we need to verify the server's certificate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	/* We accept only certificates signed only by the CA himself */
	SSL_CTX_set_verify_depth(ctx, 1);

	std::fill(priv.begin(), priv.end(), 0);
	std::fill(masterkey.begin(), masterkey.end(), 0);

	/* Done, return the context */
	free(pkey);
	return ctx;

fail:
	std::fill(priv.begin(), priv.end(), 0);
	std::fill(masterkey.begin(), masterkey.end(), 0);
	free(pkey);
	SSL_CTX_free(ctx);
	return NULL;
}

//-----------------------------------------------------------------
// OpenTCPConnection - Creates a TCP Connection to a TCP port
// accepting connection requests
//-----------------------------------------------------------------
TTcpConnectedPort* OpenTcpConnection(const char* remotehostname, const char* remoteportno,
	const char* ca_pem, const char* cert_pem, const char* key_pem)
{
	TTcpConnectedPort* TcpConnectedPort = NULL;
	int option, sslfd;
	BIO* sbio = NULL;
	SSL* ssl = NULL;
	SSL_CTX* ctx = NULL;
	X509* server_cert = NULL;
	struct addrinfo* result = NULL;
	struct addrinfo hints;
	struct timeval tv;
	fd_set fdset;
	long arg;
	u_long mode;

	WSADATA wsaData;
	int iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		delete TcpConnectedPort;
		printf("WSAStartup failed: %d", iResult);
		return(NULL);
	}

	TcpConnectedPort = new (std::nothrow) TTcpConnectedPort;

	if (TcpConnectedPort == NULL)
	{
		fprintf(stderr, "TUdpPort memory allocation failed\n");
		return(NULL);
	}

	/* initialization of TcpConnectedPort dynamiclly allocated */
	TcpConnectedPort->ConnectedFd = BAD_SOCKET_FD;
	TcpConnectedPort->isSsl = FALSE;
	TcpConnectedPort->ssl = NULL;
	TcpConnectedPort->ctx = NULL;

	TcpConnectedPort->ConnectedFd = socket(AF_INET, SOCK_STREAM, 0);
	if (TcpConnectedPort->ConnectedFd == BAD_SOCKET_FD)
	{
		printf("socket failed");
		goto error;
	}

	option = 200 * 1024;
	if (setsockopt(TcpConnectedPort->ConnectedFd, SOL_SOCKET, SO_SNDBUF, (char*)&option, sizeof(option)) == -1)
	{
		printf("setsockopt SO_SNDBUF failed\n");
		goto error;
	}

	option = 200 * 1024;
	if (setsockopt(TcpConnectedPort->ConnectedFd, SOL_SOCKET, SO_RCVBUF, (char*)&option, sizeof(option)) == -1)
	{
		printf("setsockopt SO_RCVBUF failed\n");
		goto error;
	}

	option = 1;
	if (setsockopt(TcpConnectedPort->ConnectedFd, IPPROTO_TCP, TCP_NODELAY, (char*)&option, sizeof(option)) < 0)
	{
		printf("setsockopt TCP_NODELAY failed\n");
		goto error;
	}

	if (ca_pem != NULL && cert_pem != NULL && key_pem != NULL) {
		/* Initialize OpenSSL */
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();

		/* Get a context */
		if (!(ctx = get_client_context(ca_pem, cert_pem, key_pem))) {
			printf("get_client_context failed\n");
			goto error;
		}

		/* Get a BIO */
		if (!(sbio = BIO_new_ssl_connect(ctx))) {
			printf("BIO_new_ssl_connect failed\n");
			goto error_new_ssl_connect;
		}

		/* Get the SSL handle from the BIO */
		BIO_get_ssl(sbio, &ssl);

		/* Connect to the server */
		char conn_str[128];
		snprintf(conn_str, sizeof(conn_str), "%s:%s", remotehostname, remoteportno);
		if (BIO_set_conn_hostname(sbio, conn_str) != 1) {
			printf("Could not connecto to the server\n");
			goto error_connect;
		}

		/* set non blocking IO */
		BIO_set_nbio(sbio, 1);

		if (BIO_do_connect(sbio) <= 0) {
			if (!BIO_should_retry(sbio)) {
				printf("BIO_do_connect failed\n");
				goto error_connect;
			}

			if (BIO_get_fd(sbio, &sslfd) < 0) {
				printf("BIO_get_fd failed\n");
				goto error_connect;
			}

			FD_ZERO(&fdset);
			FD_SET(sslfd, &fdset);
			tv.tv_sec = 2;  /* 2 second timeout */
			tv.tv_usec = 0;

			if (select(sslfd + 1, NULL, &fdset, NULL, &tv) == 1) { // check write fds
				int so_error = 0;
				socklen_t len = sizeof(so_error);

				getsockopt(sslfd, SOL_SOCKET, SO_ERROR, (char *) & so_error, &len);

				if (so_error != 0) {
					printf("connection error\n");
					goto error_connect;
				}
			}
			else {
				printf("connection timeout or error\n");
				goto error_connect;
			}
		}

		DWORD start = timeGetTime();;
		while (1) {
			if (SSL_do_handshake(ssl) == 1) {
				break;
			}

			DWORD end = timeGetTime();
	
		    if ((end-start)%60 > 2) {
				printf("SSL Handshake failed\n");
				goto error_connect;
			}

			Sleep(1000);
		}

	    mode = 0;
	    ioctlsocket(sslfd, FIONBIO, &mode);
		BIO_set_nbio(sbio, 0);

		/* Verify that SSL handshake completed successfully */
		if (SSL_get_verify_result(ssl) != X509_V_OK) {
			printf("Verification of handshake failed\n");
			goto error_connect;
		}

		/* Host name Verification is required!!!*/
		// Recover the server's certificate
		server_cert = SSL_get_peer_certificate(ssl);
		if (server_cert == NULL) {
			// The handshake was successful although the server did not provide a certificate
			// Most likely using an insecure anonymous cipher suite... get out!
			printf("SSL_get_peer_certificate failed\n");
			goto error_verify_cert;
		}

		// Validate the hostname
		if (validate_hostname(TARGET_SERVER, server_cert) != MatchFound) {
			printf("Hostname validation failed\n");
			goto error_verify_hostname;
		}

		/* Inform the user that we've successfully connected */
		printf("SSL handshake successful with %s. %s", conn_str, get_ssl_version_str(ssl));
		TcpConnectedPort->isSsl = true;
		TcpConnectedPort->ssl = ssl;
		TcpConnectedPort->ctx = ctx;
	}
	else {
		// set addr info to connect
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		if (getaddrinfo(remotehostname, remoteportno, &hints, &result) != 0) {
			printf("getaddrinfo failed");
			goto error;
		}

		if (result == NULL) {
			printf("getaddrinfo result is NULL\n");
			goto error;
		}

		if (connect(TcpConnectedPort->ConnectedFd, result->ai_addr, (int)result->ai_addrlen) < 0)
		{
			CloseTcpConnectedPort(&TcpConnectedPort);
			freeaddrinfo(result);
			perror("connect failed");
			return(NULL);
		}
		freeaddrinfo(result);

		printf("success TCP connection\n");
	}
	
	return TcpConnectedPort;

	/* Cleanup and error */
error_verify_hostname:
	if (server_cert) {
		X509_free(server_cert);
	}
error_verify_cert:
	BIO_ssl_shutdown(sbio);
error_connect:
	BIO_free_all(sbio);
error_new_ssl_connect:
	SSL_CTX_free(ctx);
error:
	if (result != NULL) {
		freeaddrinfo(result);
	}

	CloseTcpConnectedPort(&TcpConnectedPort);
	return NULL;
}
//-----------------------------------------------------------------
// END OpenTcpConnection
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// CloseTcpConnectedPort - Closes the specified TCP connected port
//-----------------------------------------------------------------
void CloseTcpConnectedPort(TTcpConnectedPort** TcpConnectedPort)
{
	if (TcpConnectedPort == NULL || (*TcpConnectedPort) == NULL) {
		return;
	}

	if ((*TcpConnectedPort)->ConnectedFd != BAD_SOCKET_FD) {

		if ((*TcpConnectedPort)->isSsl) {
			/* SSL Finalize */
			if ((*TcpConnectedPort)->ssl)
			{
				SSL_shutdown((*TcpConnectedPort)->ssl);
				SSL_free((*TcpConnectedPort)->ssl);
			}
			if ((*TcpConnectedPort)->ctx)
			{
				SSL_CTX_free((*TcpConnectedPort)->ctx);
			}
		}
		CLOSE_SOCKET((*TcpConnectedPort)->ConnectedFd);
		(*TcpConnectedPort)->ConnectedFd = BAD_SOCKET_FD;
	}

	free(*TcpConnectedPort);
	(*TcpConnectedPort) = NULL;
	//WSACleanup();
}
//-----------------------------------------------------------------
// END CloseTcpListenPort
//-----------------------------------------------------------------
ssize_t ReadDataTcp(TTcpConnectedPort* TcpConnectedPort, unsigned char* data, size_t length)
{
	int ret;
	int sslfd;
	fd_set fdset;
	ssize_t bytes = 0;

	if (length > MAXINT) {
		printf("length > G_MAXINT. too long. cannot read it\n");
		return -1;
	}

	if (TcpConnectedPort->isSsl) {

		sslfd = SSL_get_fd(TcpConnectedPort->ssl);
		if (sslfd < 0) {
			printf("SSL_get_fd failed\n");
			return -1;
		}

		FD_ZERO(&fdset);
		FD_SET(sslfd, &fdset);

		for (size_t i = 0; i < length; i += bytes)
		{
			bytes = SSL_read(TcpConnectedPort->ssl, (char*)(data + i), length - i);

			if (bytes == 0)
			{
				printf("Connection closed, noramlly\n");
				return -1;
			}
			else if (bytes < 0)
			{
				int error_num = WSAGetLastError();
				if (error_num == WSAEWOULDBLOCK)
				{
					printf("WSAEWOULDBLOCK\n");
				}
				else if (error_num == WSAECONNRESET)
				{
					printf("Connection closed, WSAECONNRESET\n");
					return -1;
				}
				else
				{
					printf("recv failed: %d\n", error_num);
					return -1;
				}
			}
		}
	}
	else {
		for (size_t i = 0; i < length; i += bytes)
		{
			if ((bytes = recv(TcpConnectedPort->ConnectedFd, (char*)(data + i), (int)(length - i), 0)) == -1)
			{
				return (-1);
			}
		}
	}
	
	return length;
}
//-----------------------------------------------------------------
// END ReadDataTcp
//-----------------------------------------------------------------

//-----------------------------------------------------------------
// WriteDataTcp - Writes the specified amount TCP data
//-----------------------------------------------------------------
ssize_t WriteDataTcp(TTcpConnectedPort* TcpConnectedPort, unsigned char* data, size_t length)
{
	ssize_t total_bytes_written = 0;
	ssize_t bytes_written;

	if (length > MAXINT) {
		printf("length > G_MAXINT. too long. cannot write it\n");
		goto exit;
	}

	while (total_bytes_written != (ssize_t)length)
	{
		if (TcpConnectedPort->isSsl) {
			bytes_written = SSL_write(TcpConnectedPort->ssl,
				(char*)(data + total_bytes_written),
				(int)length - total_bytes_written);
		}
		else {
			bytes_written = send(TcpConnectedPort->ConnectedFd,
				(char*)(data + total_bytes_written),
				length - total_bytes_written, 0);
		}
		
		if (bytes_written == -1)
		{
			return(-1);
		}

		total_bytes_written += bytes_written;
	}

exit:
	return total_bytes_written;
}
//-----------------------------------------------------------------
// END WriteDataTcp
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// BytesAvailableTcp - Reads the bytes available 
//-----------------------------------------------------------------
ssize_t BytesAvailableTcp(TTcpConnectedPort* TcpConnectedPort)
{
    unsigned long n = -1;
    
    if (ioctlsocket(TcpConnectedPort->ConnectedFd, FIONREAD, &n) <0)
    {
        printf("BytesAvailableTcp: error %d\n", WSAGetLastError());
        return -1;
    }
  
    return((ssize_t)n);
}
//-----------------------------------------------------------------
// END BytesAvailableTcp 
//-----------------------------------------------------------------
// 
/* If successful, return zero. otherwize error return */
int setNonBlockingSock(TTcpConnectedPort* TcpConnectedPort)
{
	u_long nonBlockingMode = 1;
	int sk_fd;
	if (TcpConnectedPort->isSsl)
	{
		sk_fd = SSL_get_fd(TcpConnectedPort->ssl);
	}
	else
	{
		sk_fd = TcpConnectedPort->ConnectedFd;
	}

	if (sk_fd < 0) {
		printf("sk fd failed\n");
		return -1;
	}

	return ioctlsocket(sk_fd, FIONBIO, &nonBlockingMode);
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------