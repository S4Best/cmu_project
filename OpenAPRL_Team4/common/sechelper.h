#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <limits>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <io.h>
#include <fstream>
#include <fcntl.h>
#include <WinSock2.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
static const unsigned int AES_GCM_TAG_SIZE = 16;
static const unsigned int AES_BLOCK_SIZE = 16;
constexpr size_t kGcmIvLength = 96 / 8;
constexpr size_t kGcmIvSizeBytes = 96 / 8;
constexpr size_t kValueSize = 32768;
static std::string masterkey_path = "keys/MasterKey";
static std::string CertFile = "keys/client/client.cert";
static std::string ClientKeyFile = "keys/client/client.key";
static std::string EncClientKeyFile = "keys/client/client_enc.key";
static std::string CAFile = "keys/ca/chain.crt";
static std::string ServerKeyFile = "keys/server/server.key";
static std::string EncServerKeyFile = "keys/server/server_enc.key";
static std::string AlertLogFile = "alert.log";
static std::string EncAlertLogFile = "alert_enc.log";

static std::string AccountDBKeyFile = "keys/encKey/account_key.json";
static std::string EncAccountDBKeyFile = "keys/encKey/account_key_enc.json";
static std::string OtpDBKeyFile = "keys/encKey/otpbase_key.json";
static std::string EncOtpDBKeyFile = "keys/encKey/otpbase_key_enc.json";
static std::string PlateDBKeyFile = "keys/encKey/plate_key.json";
static std::string EncPlateDBKeyFile = "keys/encKey/plate_key_enc.json";


typedef struct blobv1 {
    uint8_t flags;
    uint8_t info;
    uint8_t initialization_vector[AES_BLOCK_SIZE];
    uint8_t tag[AES_GCM_TAG_SIZE];
    int32_t length;
    uint8_t value[kValueSize + AES_BLOCK_SIZE];
}Blob;

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

int client_cipher_init();
int server_cipher_init();
std::string hexStr(uint8_t* data, int len);
std::vector<uint8_t> HexStringToByteArray(std::string& str);
size_t readFully(int fd, uint8_t* data, size_t size);
size_t writeFully(int fd, uint8_t* data, size_t size);
int encryptData(const std::string& filename, const uint8_t* value, size_t valueLength, const uint8_t* info, uint8_t infoLength, const std::vector<uint8_t>& aes_key, Blob* rawBlob);
int decryptDatatoBuffer(const std::string& filename, const std::vector<uint8_t>& aes_key, std::vector<uint8_t>& decData);
int decryptDatatoFile(const std::string& filename, const std::vector<uint8_t>& aes_key, Blob* rawBlob);
int writeBlob(const std::string& filename, Blob* rawBlob);
int readBlob(const std::string& filename, Blob* rawBlob);
int loadMasterBlob(const std::string& filename, Blob* mBlob);
int encryptAllData(const std::string& filename, Blob* masterkey);

template < typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
