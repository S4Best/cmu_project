
#include "sechelper.h"
#include <sys/stat.h>

#define ssize_t int
#define F_OK    0

class ArrayEraser {
    public:
          ArrayEraser(uint8_t * arr, size_t size) : mArr(arr), mSize(size) {}
          ~ArrayEraser() { std::fill(mArr, mArr + mSize, 0); }
    
    private:
          volatile uint8_t * mArr;
          size_t mSize;
 };

std::string hexStr(uint8_t* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i(0); i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}

std::vector<uint8_t> HexStringToByteArray(std::string& data) {
    std::stringstream ss;
    ss << data;

    std::vector<uint8_t> resBytes;
    size_t count = 0;
    const auto len = data.size();
    while (ss.good() && count < len)
    {
        unsigned short num;
        char hexNum[2];
        ss.read(hexNum, 2);
        sscanf_s(hexNum, "%2hX", &num);
        resBytes.push_back(static_cast<uint8_t>(num));
        count += 2;
    }

    return resBytes;
}

int AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len,
    const std::vector<uint8_t>& key, const uint8_t* iv, uint8_t* tag) {

    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    EVP_EncryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key.data(), iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);

    std::unique_ptr<uint8_t[]> out_tmp(new uint8_t[len]);
    uint8_t* out_pos = out_tmp.get();
    int out_len;

    EVP_EncryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    EVP_EncryptFinal_ex(ctx.get(), out_pos, &out_len);
    out_pos += out_len;
    if (out_pos - out_tmp.get() != static_cast<ssize_t>(len)) {
        printf("Encrypted ciphertext is the wrong size, expected %zu, got %zd\n", len, out_pos - out_tmp.get());
        return -1;
    }

    std::copy(out_tmp.get(), out_pos, out);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag);

    return 1;
}

int AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len,
    const std::vector<uint8_t> key, const uint8_t* iv,
    const uint8_t* tag) {

    const EVP_CIPHER* cipher = EVP_aes_256_gcm();

    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);

    EVP_DecryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key.data(), iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, const_cast<uint8_t*>(tag));

    std::unique_ptr<uint8_t[]> out_tmp(new uint8_t[len]);
    ArrayEraser out_eraser(out_tmp.get(), len);
    uint8_t* out_pos = out_tmp.get();

    int out_len;

    EVP_DecryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    if (!EVP_DecryptFinal_ex(ctx.get(), out_pos, &out_len)) {
        printf("Failed to decrypt blob; ciphertext or tag is likely corrupted\n");
        return -1;
    }
    out_pos += out_len;
    if (out_pos - out_tmp.get() != static_cast<ssize_t>(len)) {
        printf("Encrypted plaintext is the wrong size, expected %zu, got %zd\n", len, out_pos - out_tmp.get());
        return -1;
    }

    std::copy(out_tmp.get(), out_pos, out);

    return 1;
}

size_t readFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    int flag = 0;
    while (remaining > 0) {
        ssize_t n = _read(fd, data, remaining);
        if (n <= 0) {
            if (flag < 3)
            {
                flag++;
            }
            else {
                return size - remaining;
            }
        }
        data += n;
        remaining -= n;
    }
    return size;
}

size_t writeFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = _write(fd, data, remaining);
        if (n < 0) {
            return size - remaining;
        }
        data += n;
        remaining -= n;
    }
    //if (TEMP_FAILURE_RETRY(fsync(fd)) == -1) {
    //    printf("fsync failed: %s",  strerror(errno));
    //    return 0;
    //}
    return size;
}

bool generateSalt(std::vector<uint8_t>& mSalt) {
    return RAND_bytes(mSalt.data(), mSalt.size());
}

bool generateMasterKey(std::vector<uint8_t>& key) {
    key.resize(KEY_SIZE);
    if (!RAND_bytes(key.data(), key.size())) {
        return false;
    }
    return true;
}

void initBlob(const uint8_t* value, size_t valueLength, const uint8_t* info, uint8_t infoLength,Blob* rawBlob)
{
    memset(reinterpret_cast<void*>(rawBlob), 0, sizeof(Blob));

    if (valueLength > kValueSize) {
        valueLength = kValueSize;
    }
    if (infoLength + valueLength > kValueSize) {
        infoLength = kValueSize - valueLength;
    }
    rawBlob->length = valueLength;
    memcpy(rawBlob->value, value, valueLength);

    rawBlob->info = infoLength;
    memcpy(rawBlob->value + valueLength, info, infoLength);
}



int writeBlob(const std::string& filename, Blob* rawBlob) {
    const size_t dataLength = rawBlob->length;
    size_t fileLength = offsetof(blobv1, value) + dataLength + rawBlob->info;

    int fh;
    int out = _sopen_s(&fh, filename.c_str(), O_WRONLY | O_TRUNC | O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE);
    if (out < 0) {
        printf("could not open temp file: %s for writing blob file: %s\n", filename.c_str(), filename.c_str());
        return -1;
    }
#if 1
    std::string str = hexStr(reinterpret_cast<uint8_t*>(rawBlob), fileLength);
    const size_t writtenBytes = writeFully(fh, reinterpret_cast<uint8_t*>(const_cast<char*>(str.c_str())), str.size());
#else
    const size_t writtenBytes = writeFully(fh, reinterpret_cast<uint8_t*>(rawBlob), fileLength);
#endif
    if (_close(fh) != 0) {
        return -1;
    }
    if (writtenBytes != str.size()) {
        printf("blob not fully written %u != %u\n", (unsigned int)writtenBytes, (unsigned int)str.size());
        return -1;
    }

    _flushall();
    return writtenBytes;
}

int readBlob(const std::string& filename, Blob* rawBlob) {
    size_t result;
    size_t fileLength;
    
    std::vector<uint8_t> hexkeyblob;
    std::fill(hexkeyblob.begin(), hexkeyblob.end(), 0);
    std::vector<uint8_t> keyblob;
    std::fill(keyblob.begin(), keyblob.end(), 0);

    std::fstream inputfile(filename);

    if (inputfile.is_open()) {
        std::copy(std::istream_iterator<uint8_t>(inputfile), std::istream_iterator<uint8_t>(), back_inserter(hexkeyblob));
        inputfile.close();
    }
    else {
        std::cout << "Error opening file" << std::endl;
        return -1;
    }

    std::string str(hexkeyblob.begin(), hexkeyblob.end());
   // std::fill(keyblob.begin(), keyblob.end(), 0);
    keyblob = HexStringToByteArray(str);
    if (keyblob.size() < 0)
    {
        printf("hexstring to bytearray failed\n");
        return -1;
    }
    memcpy(rawBlob, keyblob.data(), keyblob.size());
    fileLength = keyblob.size();

    if (fileLength == 0) {
        printf("VALUE_CORRUPTED file length == 0");
        return -1;
    }
   
    if (fileLength < offsetof(blobv1, value)) {
        printf("VALUE_CORRUPTED blob file too short: %u\n", (unsigned int)fileLength);
        return -1;
    }
 
    memcpy((void *)rawBlob, (void *)keyblob.data(), fileLength);
    //printf("dataLength on readBlob =%d,fileLength=%d\n", rawBlob->length, fileLength);

    return fileLength;
}

int decryptDatatoBuffer(const std::string& filename, const std::vector<uint8_t>& aes_key, std::vector<uint8_t>& decData) {
    int result = 0, fileLength = 0;

    Blob rawBlob;
    memset(&rawBlob, 0, sizeof(Blob));

    std::vector<uint8_t> encData;
    std::fill(encData.begin(), encData.end(), 0);
    std::vector<uint8_t> decprivatekey;
    std::fill(decprivatekey.begin(), decprivatekey.end(), 0);

    fileLength = readBlob(filename, &rawBlob);
    if (fileLength < 1) {
        printf("decrypt blob failed to read encrypted private key : %d\n", (int)fileLength);
        return fileLength;
    }

    const ssize_t encLength = rawBlob.length;

    result = AES_gcm_decrypt(rawBlob.value /* in */, rawBlob.value /* out */, encLength,
        aes_key, rawBlob.initialization_vector, rawBlob.tag);
    if (result != 1) {
        printf("failed to decrypt data : %d", (int)result);
        return result;
    }
    ssize_t rawLength = rawBlob.length;


    std::vector<uint8_t>::iterator valueBytes;
    decData.resize(rawLength);
    valueBytes = decData.begin();
    for (int i = 0; i < rawLength; i++) {
        valueBytes[i] = rawBlob.value[i];
    }

    //std::cout << "decrypted data:" << decData.data() << std::endl;
    return result;
}

int decryptDatatoFile(const std::string& filename, const std::vector<uint8_t>& aes_key, Blob *rawBlob) {
    //printf("Entering function % s\n", __FUNCTION__);

    int result = 0, fileLength = 0;
    std::vector<uint8_t> decData;
    std::fill(decData.begin(), decData.end(), 0);

    fileLength = readBlob(filename, rawBlob);
    if (fileLength < 1) {
        printf("decrypt blob failed to read encrypted data : %d\n", (int)fileLength);
        return result;
    }

    const ssize_t encLength = rawBlob->length;

    result = AES_gcm_decrypt(rawBlob->value /* in */, rawBlob->value /* out */, encLength,
        aes_key, rawBlob->initialization_vector, rawBlob->tag);
    if (result != 1) {
        printf("failed to decrypt data : %d", (int)result);
        return result;
    }
    ssize_t rawLength = rawBlob->length;


    std::vector<uint8_t>::iterator valueBytes;
    decData.resize(rawLength);
    valueBytes = decData.begin();
    for (int i = 0; i < rawLength; i++) {
        valueBytes[i] = rawBlob->value[i];
    }

    size_t iSeperator = filename.find('.');

    std::string sName1 = filename.substr(0, iSeperator);
    std::size_t pos = sName1.rfind('_');

    std::string sName2 = sName1.substr(0, pos);
    std::string sName3 = filename.substr(iSeperator + 1);
    std::string orgFilename = sName2 + "." + sName3;

    std::ofstream ofile(orgFilename);
    ofile << decData.data();
    ofile.close();

    //std::cout << "successfully stored original data on decryptDatatoFile" << std::endl;
    return result;
}

int encryptData(const std::string& filename, const uint8_t* value, size_t valueLength,const uint8_t* info, uint8_t infoLength, const std::vector<uint8_t>& aes_key, Blob* rawBlob) {
    memset(rawBlob->initialization_vector, 0, AES_BLOCK_SIZE);
    if (!RAND_bytes(rawBlob->initialization_vector, kGcmIvSizeBytes)) {
        printf("Filed to make iv to encrypt blob\n");
        return -1;
    }

    int result = AES_gcm_encrypt(value, rawBlob->value, valueLength, aes_key, rawBlob->initialization_vector, rawBlob->tag);
    if (result != 1) {
        printf("Encrypt blob failed to read blob : %d\n", (int)result);
        return -1;
    }

    result = writeBlob(filename, rawBlob);
    if (result < 1) {
        printf("Encrypt blob failed to save : %d\n", (int)result);
        return -1;
    }

    return 1;
}


int encryptAllData(const std::string& filename, Blob* masterkey)
{
    std::vector<uint8_t> mEncData;
    std::vector<uint8_t> pSalt;
    std::vector<uint8_t> mMasterkey;
    int result = 0;

    ssize_t rawLength = masterkey->length;
    std::vector<uint8_t>::iterator valueBytes;
    mMasterkey.resize(rawLength);
    valueBytes = mMasterkey.begin();
    for (int i = 0; i < rawLength; i++) {
        valueBytes[i] = masterkey->value[i];
    }

    //read privatekey
    std::fstream inputfile(filename);

    if (inputfile.is_open()) {
        std::copy(std::istream_iterator<uint8_t>(inputfile), std::istream_iterator<uint8_t>(), back_inserter(mEncData));
        inputfile.close();
    }
    else {
        std::cout << "Error opening file" << std::endl;
        return -1;
    }

    //std::cout << "private key:" << privatekey.data() << std::endl << std::endl;
    size_t iSeperator = filename.find('.');

    std::string sName1 = filename.substr(0, iSeperator);
    std::string sName2 = filename.substr(iSeperator + 1);
    std::string encFilename = sName1 + "_enc." + sName2;

    generateSalt(pSalt);
    Blob encdata;
    initBlob(mEncData.data(), mEncData.size(), pSalt.data(), pSalt.size(), &encdata);

    result = encryptData(encFilename, mEncData.data(), mEncData.size(), pSalt.data(), pSalt.size(), mMasterkey, &encdata);
    if (result < 1) {
        printf("encryptPriv failed : %d\n", (int)result);
        return -1;
    }

    return 1;
}

int loadMasterBlob(const std::string& filename, Blob* mBlob)
{
    std::vector<uint8_t> mKey;
    std::vector<uint8_t> salt;
    uint8_t valueLength, infoLength;
    int result = 0;

    if (_access(filename.c_str(), F_OK) == 0) {

        result = readBlob(filename, mBlob);
        if (result < 1) {
            printf("readBlob failed to read masterkey : %d\n", (int)result);
            return -1;
        }
    }
    else {
        std::fill(mKey.begin(), mKey.end(), 0);
        std::fill(salt.begin(), salt.end(), 0);

        generateMasterKey(mKey);
        generateSalt(salt);

        infoLength = salt.size();
        valueLength = mKey.size();

        memset(mBlob, 0, sizeof(Blob));
        initBlob(mKey.data(), mKey.size(), salt.data(), salt.size(), mBlob);
        result = writeBlob(filename, mBlob);
        if (result < 0)
        {
            printf("failed to write masterkey : %d\n", (int)result);
            return -1;
        }
    }
    return 1;
}

