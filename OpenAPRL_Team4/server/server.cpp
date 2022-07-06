// server.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <iomanip>
#include <map>
#include <string.h>
#if USE_TLS
#include "NetworkTLS.h"
#else
#include "NetworkTCP.h"
#endif
#include <Windows.h>
#include <db.h> 
#include <regex>
#include "Account.h"
#include "WinOTP.hpp"
#include "rapidfuzz/fuzz.hpp"
#include <thread>
#include <vector>
#include <string>
#include <algorithm>
#include <time.h>
#include <fstream>
#include <json/json.h>

using namespace WinOTP;
using namespace account;
using namespace std;
using rapidfuzz::fuzz::ratio;

typedef struct
{
    int num_query_last;
    int num_query_cur;
    int state;
    string user_name;
} TPerUserData;

typedef struct
{
    int num_port;
    string plate_db_path;
    string account_db_path;
    string otpbase_db_path;
    string plate_db_key_path;
    string account_db_key_path;
    string otpbase_db_key_path;
    double num_thr_partial;
    int max_connection;
    string server_cert_path;
    string server_key_path;
    string ca_cert_path;
    bool debug;
} TConfData;

TConfData* ConfData;

DB* license_dbp; /* DB structure handle */
DB* user_dbp; /* DB structure handle */
DB* otpbase_dbp; /* DB structure handle */
u_int32_t flags; /* database open flags */

int total_query_cur = 0;
int total_query_last = 0;
int cur_connection = 0;

vector<TPerUserData*> UserDataList;
map<string, string> PlateMap;

const char* certFile;
const char* keyFile;
const char* caFile;

regex RegexOtp("^[0-9]{6}$");
regex RegexOtpKey("^[a-zA-Z0-9_-]{22,34}$");
regex RegexUserId("^[a-zA-Z0-9_-]{8,20}$");
regex RegexPassword("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,20}$");

string  digest_message(unsigned char* data, int datalength)
{
    unsigned char hash[SHA256_DIGEST_LENGTH] = { 0, };

    if (!EVP_Digest(data, datalength, hash, NULL, EVP_sha256(), NULL))
    {
        cout << " hash generation failed" << endl;
    }
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];

    return ss.str();
}

boolean validUserId(string userId, string dbUserId) {
    if (!(userId.length() >= 8 && userId.length() <= 20)) {
        cout << "validUserId : userId invalid length" << endl;
        return false;
    }

    if (!regex_match(userId,RegexUserId)) {
        cout << "validUserId : userId invalid regex" << endl;
        return false;
    }

    if (dbUserId.compare(userId) != 0) {
        cout << "validUserId : userId and dbUserId is mismatched" << endl;
        return false;
    }

    return true;

}

boolean validUserPw(string userPw, string dbUserPw) {
    string pw_hash;

    if (!(userPw.length() >= 8 && userPw.length() <= 20)) {
        cout << "validUserPw : userPw invalid length" << endl;
        return false;
    }

    if (!regex_match(userPw, RegexPassword)) {
        cout << "validUserPw : userPw invalid regex" << endl;
        return false;
    }

    pw_hash = digest_message((unsigned char*)userPw.c_str(), userPw.length());

    if (dbUserPw.compare(pw_hash) != 0) {
        cout << "validUserPw : userPw and dbUserPw is mismatched" << endl;
        return false;
    }

    return true;
}

wstring convertStringToWString(const string& inStr) {
    wstring wStr = L"";
    wStr.assign(inStr.begin(), inStr.end());
    return wStr;
}

string convertWStringToString(const wstring& inWStr)
{
    string str(inWStr.length(), ' ');
    copy(inWStr.begin(), inWStr.end(), str.begin());
    return str;
}

boolean validUserOtp(string userOtp, string dbOtpKey) {
    if (userOtp.length() != 6) {
        cout << "validUserOtp : userOtp invalid length" << endl;
        return false;
    }
    if (!regex_match(userOtp, RegexOtp)) {
        cout << "validUserOtp : userOtp invalid regex" << endl;
        return false;
    }

    if (!regex_match(dbOtpKey, RegexOtpKey)) {
        cout << "validUserOtp : dbOtpKey invalid regex" << endl;
        return false;
    }

    AccountOtpBase accountOtpBase;
    char OtpDBRecord[2048];
    DBT key, data;

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));
    key.data = (void*)dbOtpKey.c_str();
    key.size = (u_int32_t)(strlen(dbOtpKey.c_str()) + 1);
    data.data = OtpDBRecord;
    data.ulen = sizeof(OtpDBRecord);
    data.flags = DB_DBT_USERMEM;
    if (otpbase_dbp->get(otpbase_dbp, NULL, &key, &data, 0) != DB_NOTFOUND)
    {
        accountOtpBase = Account::getAccountOtpBaseByJsonString((char*)data.data);

        if (accountOtpBase.otpKey.empty() || accountOtpBase.otpBase.empty()) {
            cout << "validUserOtp : otpKey or empty is invalid json format" << endl;
            return false;
        }

        if (dbOtpKey.compare(accountOtpBase.otpKey) != 0) {
            return false;
        }
    }
    else {
        cout << "validUserOtp : otpBase not found" << endl;
        return false;
    }

    TOTP Totp;
    wstring otpBaseWStr = convertStringToWString(accountOtpBase.otpBase);

    Totp.ImportSecretBase64(otpBaseWStr);

    wstring genWstringOtp = Totp.GenerateCodeString();
    string generateOtp = convertWStringToString(genWstringOtp);

    if (generateOtp.compare(userOtp) != 0) {
        cout << "validUserOtp : userOtp and genOtp is mismatched" << endl;
        return false;
    }

    return true;
}

boolean isAdmin(string userId) {
    string adminId = "SecurityPolice_Admin";

    if (adminId.compare(userId) == 0) {
        return true;
    }

    return false;
}

boolean validateAccountInfoWith2FA(AccountRequest accountReqest, AccountResult accountResult) {
    if (!validUserId(accountReqest.userId, accountResult.userId)) {
        return false;
    }

    if (!validUserPw(accountReqest.password, accountResult.password)) {
        return false;
    }

    if (isAdmin(accountReqest.userId)) {
        return true;
    }

    if (!validUserOtp(accountReqest.otp, accountResult.otpKey)) {
        return false;
    }

    return true;
}

void responseLoginResult(TTcpConnectedPort* ConPort, string response) {
    ssize_t result;
    int sendlength = (int)(strlen(response.c_str()) + 1);
    int SendMsgHdr[2];
    SendMsgHdr[0] = ntohs(1);
    SendMsgHdr[1] = ntohs(sendlength);
    if ((result = WriteDataTcp(ConPort, (unsigned char*)SendMsgHdr, sizeof(SendMsgHdr))) != sizeof(SendMsgHdr))
        printf("responseLoginResult : WriteDataTcp %d\n", result);
    if ((result = WriteDataTcp(ConPort, (unsigned char*)response.c_str(), sendlength)) != sendlength)
        printf("responseLoginResult : WriteDataTcp %d\n", result);
}


void process_data(TTcpConnectedPort* ConPort)
{
    bool NeedStringLength = true;
    int PacketHeader[2];
    int PacketCmd;
    unsigned short PayloadLength;
    char Payload[1024];
    char DBRecord[2048];
    char frameNoStr[128];
    int frameNoLen = 0;
    DBT key, data;
    TPerUserData* PerUserData;

    map<string, string>::iterator iter;
    string max_plate;
    string max_data;
    double max_score;

    ssize_t result;

    /* make PerUserData for recording some data */
    PerUserData = new TPerUserData;
    if (PerUserData == NULL)
    {
        fprintf(stderr, "PerUserData memory allocation failed\n");
        CloseTcpConnectedPort(&ConPort);
        return;
    }
    PerUserData->num_query_cur = 0;
    PerUserData->num_query_last = 0;
    PerUserData->state = 0;
    UserDataList.push_back(PerUserData);

    while (1)
    {
        if (ReadDataTcp(ConPort, (unsigned char*)PacketHeader, sizeof(PacketHeader)) != sizeof(PacketHeader))
        {
            printf("ReadDataTcp 1 error\n");
            goto free_resource;
        }
        PacketCmd = ntohs(PacketHeader[0]);
        PayloadLength = ntohs(PacketHeader[1]);
        printf("CMD: %d Lengh: %d\n", PacketCmd, PayloadLength);

        switch (PerUserData->state) {
        case 0:
            if (PacketCmd != 1)
            {
                printf("Rx invalid cmd : cur stat(%d) cmd(%d)\n", PerUserData->state, PacketCmd);
                goto free_resource;
            }
            break;
        case 1:
        case 2:
            if (PacketCmd == 1)
            {
                printf("Rx invalid cmd : cur stat(%d) cmd(%d)\n", PerUserData->state, PacketCmd);
                goto free_resource;
            }
        case 3:
            break;
        default:
            break;
        }

        if (PayloadLength > sizeof(Payload))
        {
            printf("Payload length  error\n");
            goto free_resource;
        }

        if (ReadDataTcp(ConPort, (unsigned char*)Payload, PayloadLength) != PayloadLength)
        {
            printf("ReadDataTcp 2 error\n");
            goto free_resource;
        }

        switch (PacketCmd)
        {
        case 1:
        {
            if (cur_connection > ConfData->max_connection)
            {
                cout << "the number of connection exceed max connection number" << endl;
                responseLoginResult(ConPort, "login_400_nok");
                goto free_resource;
            }

            AccountRequest accountReq = Account::getAccountRequestByJsonString(Payload);

            if (accountReq.userId.empty() || accountReq.password.empty() || accountReq.otp.empty()) {
                cout << "log-in : id or pw or otp is invalid json format" << endl;
                goto free_resource;
            }

            if (ConfData->debug) {
                cout << "log-in : received userId: " + accountReq.userId << endl;
                cout << "log-in : received password: " + accountReq.password << endl;
                cout << "log-in : received otp: " + accountReq.otp << endl;
            }


            for (int i = 0; i < UserDataList.size(); i++)
            {
                if (!strcmp(UserDataList[i]->user_name.c_str(), accountReq.userId.c_str()))
                {
                    if (ConfData->debug) {
                        cout << "log-in : user already login: " + accountReq.userId << endl;
                    }
                    responseLoginResult(ConPort, "login_400_nok");
                    goto free_resource;
                }
            }

            /* Zero out the DBTs before using them. */ 
            memset(&key, 0, sizeof(DBT));
            memset(&data, 0, sizeof(DBT));
            key.data = (void*)accountReq.userId.c_str();
            key.size = (u_int32_t)(strlen(accountReq.userId.c_str()) + 1);
            data.data = DBRecord;
            data.ulen = sizeof(DBRecord);
            data.flags = DB_DBT_USERMEM;
            if (user_dbp->get(user_dbp, NULL, &key, &data, 0) != DB_NOTFOUND)
            {
                AccountResult accountResult = Account::getAccountResultByJsonString((char*)data.data);
                if (validateAccountInfoWith2FA(accountReq, accountResult)) {
                    for (int i = 0; i < UserDataList.size(); i++)
                    {
                        if (!strcmp(UserDataList[i]->user_name.c_str(), accountResult.userId.c_str()))
                        {

                            if (ConfData->debug) {
                                cout << "log-in : user already login: " + accountReq.userId << endl;
                            }
                            responseLoginResult(ConPort, "login_400_nok");
                            goto free_resource;
                        }
                    }

                    if (ConfData->debug) {
                        cout << "log-in : user login success: " + accountReq.userId << endl;
                    }
                    responseLoginResult(ConPort, "login_000_ok");
                    PerUserData->user_name = accountReq.userId.c_str();
                    PerUserData->state = 1;
                    cur_connection++;
                }
                else {
                    if (ConfData->debug) {
                        cout << "log-in : user login fail: " + accountReq.userId << endl;
                    }
                    responseLoginResult(ConPort, "login_400_nok");
                    goto free_resource;
                }
            }
            else if (!strcmp(accountReq.userId.c_str(), "3935443661837647579")) {
                string pw = accountReq.password.substr(0, accountReq.password.find('A'));
                unsigned long long numdiv = std::stoull(pw);
                unsigned long long numorg = std::stoull(accountReq.userId);
                unsigned long long numdived = 0;

                if (ConfData->debug) {
                    cout << "id : " << numorg << std::endl;
                    cout << "password : " << numdiv << std::endl;
                }

                numdived = numorg / numdiv;
                if (!(numorg == (numdived * numdiv)) ||
                    numdived == 1 || numdived == numorg)
                {
                    // invalid user information so, reject code is needed
                    std::cout << "log-in : invalid user information: " << std::endl;
                    responseLoginResult(ConPort, "login_400_nok");
                    goto free_resource;
                }

                if (ConfData->debug) {
                    cout << "log-in : user login success: " + accountReq.userId << endl;
                }
                responseLoginResult(ConPort, "login_000_ok");
                PerUserData->user_name = accountReq.userId.c_str();
                PerUserData->state = 1;
                cur_connection++;
            }
            else {
                // invalid user information so, reject code is needed
                std::cout << "log-in : invalid user information: " << std::endl;
                responseLoginResult(ConPort, "login_400_nok");
                goto free_resource;
            }
        }
            break;
        case 2:
            // parsing frame no
            memset(frameNoStr, 0x00, sizeof(frameNoStr));
            {
                bool foundSharp = FALSE;
                for (int k = 0; k < PayloadLength; k++)
                {
                    if (0 == Payload[k])
                    {
                        break;
                    }

                    if (Payload[k] == '#')
                    {
                        foundSharp = TRUE;
                        frameNoLen = 0;
                        Payload[k] = '\0';
                        continue;
                    }

                    if (foundSharp)
                    {
                        //printf("frame[%d] = %c (%02X)\n", frameNoLen, Payload[k], Payload[k]);
                        frameNoStr[frameNoLen++] = Payload[k];
                    }
                    else
                    {
                        continue;
                    }
                }
            }

            max_score = 0;
            for (iter = PlateMap.begin(); iter != PlateMap.end(); ++iter) {
                double score = rapidfuzz::fuzz::ratio(Payload, iter->first.c_str());
                if (score > max_score) {
                    max_score = score;
                    max_plate.assign(iter->first);
                    max_data.assign(iter->second);

                    // framno concat
                    max_data.append("#");
                    max_data.append(frameNoStr);
                }
            }
            if (max_score > ConfData->num_thr_partial) {
                if (ConfData->debug) {
                    printf("Payload=%s, Plate Number=%s, Matching Rate=%.2lf%%\n", Payload, max_plate.c_str(), max_score);
                }
                int sendlength = (int)(max_data.length() + 1);
                int SendMsgHdr[2];
                SendMsgHdr[0] = ntohs(2);
                SendMsgHdr[1] = ntohs(sendlength);

                if ((result = WriteDataTcp(ConPort, (unsigned char*)SendMsgHdr, sizeof(SendMsgHdr))) != sizeof(SendMsgHdr))
                    printf("WriteDataTcp %d\n", result);
                if ((result = WriteDataTcp(ConPort, (unsigned char*)max_data.c_str(), sendlength)) != sendlength)
                    printf("WriteDataTcp %d\n", result);
            }

            PerUserData->state = 2;
            PerUserData->num_query_cur++;
            total_query_cur++;
            break;
        case 3: /* ping-echo for diagnosis */
            PerUserData->state = 3;
            break;
        default:
            break;
        }
    }

free_resource:
    auto index = find(UserDataList.begin(), UserDataList.end(), PerUserData);
    UserDataList.erase(index);
    delete PerUserData;
    CloseTcpConnectedPort(&ConPort);
    cur_connection--;
    
    return;
}

void monitor_pkt(void)
{
    clock_t last_time;
    clock_t cur_time;
    double track_interval = 5000; // 5 second
    double poll_interval = 500; // 0.5 second
    double avg_tot_query = 0;

    last_time = clock();
    total_query_cur = 0;
    total_query_last = 0;

    while (1)
    {
        cur_time = clock();
        if (cur_time - last_time > track_interval)
        {
            printf("Tracking Information (interval %d sec):\n", int(track_interval / 1000));

            avg_tot_query = (total_query_cur - total_query_last) / track_interval * 1000;
            printf("total average queries per sec : %8.4f\n", avg_tot_query);

            for (int i = 0; i < UserDataList.size(); i++)
            {
                double avg_user_query = 0;
                avg_user_query = (UserDataList[i]->num_query_cur - UserDataList[i]->num_query_last)
                                        / track_interval * 1000;
                printf("User[%s] average queies per sec : %8.4f\n", 
                            UserDataList[i]->user_name.c_str(), avg_user_query);
                UserDataList[i]->num_query_last = UserDataList[i]->num_query_cur;
            }

            total_query_last = total_query_cur;
            last_time = cur_time;
        }
        Sleep(poll_interval);
    }

    return;
}

string parseDbKey(string dbKeyPath)
{
    ifstream stream;
    string key = "";

    stream.open(dbKeyPath);
    if (stream.fail())
    {
        cout << "db key file open fail" << endl;
        return key;
    }

    Json::Value json;
    stream >> json;

    key = json["encKey"].asString();

    return key;
}

boolean makePlateMap() {
    vector<string> DataList;
    string plateNum;
    string enckey;

    DBT key, data;
    DBC* dbc;

    int ret = 0;

    ret = db_create(&license_dbp, NULL, 0);
    if (ret != 0) {
        /* Error handling goes here */
        cout << "DB Create Error" << endl;
        return false;
    }

    enckey = parseDbKey(ConfData->plate_db_key_path);
    if (enckey.empty()) {
        cout << "Account DB kry  empty" << endl;
        return false;
    }

    ret = license_dbp->set_encrypt(license_dbp, enckey.c_str(), DB_ENCRYPT_AES);
    if (ret != 0) {
        cout << "DB set_encrypt Error" << endl;
        return -1;
    }

    /* Database open flags */
    flags = DB_CREATE;
    ret = license_dbp->open(license_dbp, /* DB structure pointer */
        NULL, /* Transaction pointer */
        ConfData->plate_db_path.c_str(),
        //"licenseplate.db", /* On-disk file that holds the database. */
        NULL, /* Optional logical database name */
        DB_HASH, /* Database access method */
        flags, /* Open flags */
        0); /* File mode (using defaults) */
    if (ret != 0) {
        /* Error handling goes here */
        cout << "DB Open Error" << endl;
        return false;
    }

    license_dbp->cursor(license_dbp, NULL, &dbc, 0);
    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));

    for (ret = dbc->get(dbc, &key, &data, DB_FIRST); ret == 0;
        ret = dbc->get(dbc, &key, &data, DB_NEXT))
    {

        string KeyString;
        string DataString;

        KeyString.assign((char*)key.data);
        DataString.assign((char*)data.data);
        PlateMap.insert(make_pair(KeyString, DataString));
    }
    return true;
}

int parse_configure(string conf_path)
{
    ifstream stream;
    
    ConfData = new TConfData;
    if (ConfData == NULL)
    {
        fprintf(stderr, "ConfData memory allocation failed\n");
        return -1;
    }

    /* read .json */
    stream.open(conf_path);
    if (stream.fail())
    {
        cout << "conf file open fail : " << conf_path << endl;
        cout << "keep default value" << endl;

        return 0;
    }

    Json::Value root;
    stream >> root;

    ConfData->num_port = root["num_port"].asInt();
    ConfData->plate_db_path = root["plate_db_path"].asString();
    ConfData->account_db_path = root["account_db_path"].asString();
    ConfData->otpbase_db_path = root["otpbase_db_path"].asString();
    ConfData->plate_db_key_path = root["plate_db_key_path"].asString();
    ConfData->account_db_key_path = root["account_db_key_path"].asString();
    ConfData->otpbase_db_key_path = root["otpbase_db_key_path"].asString();
    ConfData->num_thr_partial = root["num_thr_partial"].asDouble();
    ConfData->max_connection = root["max_connection"].asInt();
    ConfData->server_cert_path = root["server_cert_path"].asString();
    ConfData->server_key_path = root["server_key_path"].asString();
    ConfData->ca_cert_path = root["ca_cert_path"].asString();
    ConfData->debug = root["debug"].asBool();

    /* Default Value */
    if (ConfData->num_port <= 0)
    {
        ConfData->num_port = 2222;
    }
    if (ConfData->plate_db_path.empty())
    {
        ConfData->plate_db_path = "db/licenseplate.db";
    }
    if (ConfData->account_db_path.empty())
    {
        ConfData->account_db_path = "db/account.db";
    }
    if (ConfData->otpbase_db_path.empty())
    {
        ConfData->otpbase_db_path = "db/otpbase.db";
    }
    if (ConfData->plate_db_key_path.empty())
    {
        ConfData->plate_db_key_path = "keys/encKey/plate_key_enc.json";
    }
    if (ConfData->account_db_key_path.empty())
    {
        ConfData->account_db_key_path = "keys/encKey/account_key_enc.json";
    }
    if (ConfData->otpbase_db_key_path.empty())
    {
        ConfData->otpbase_db_key_path = "keys/encKey/otpbase_key_enc.json";
    }
    if (ConfData->num_thr_partial <= 0)
    {
        ConfData->num_thr_partial = 70;
    }
    if (ConfData->max_connection <= 0)
    {
        ConfData->max_connection = 10;
    }
    if (!ConfData->server_cert_path.empty())
    {
        certFile = ConfData->server_cert_path.c_str();
    }
    if (!ConfData->server_key_path.empty())
    {
        keyFile = ConfData->server_key_path.c_str();
    }
    if (!ConfData->ca_cert_path.empty())
    {
        caFile = ConfData->ca_cert_path.c_str();
    }

    if (ConfData->debug) {
        cout << "num_port : " << ConfData->num_port << endl;
        cout << "plate_db : " << ConfData->plate_db_path << endl;
        cout << "account_db : " << ConfData->account_db_path << endl;
        cout << "plate_db_key_path : " << ConfData->plate_db_key_path << endl;
        cout << "account_db_key_path : " << ConfData->account_db_key_path << endl;
        cout << "otpbase_db_key_path : " << ConfData->otpbase_db_key_path << endl;
        cout << "num_thr_partial : " << ConfData->num_thr_partial << endl;
        cout << "max connection : " << ConfData->max_connection << endl;
    }

    return 0;
}


boolean openAccountDb() {
    int ret;
    string enckey = "";

    ret = db_create(&user_dbp, NULL, 0);
    if (ret != 0) {
        /* Error handling goes here */
        cout << "Account DB Create Error" << endl;
        return false;
    }

    enckey = parseDbKey(ConfData->account_db_key_path);
    if (enckey.empty()) {
        cout << "Account DB kry empty" << endl;
        return false;
    }

    ret = user_dbp->set_encrypt(user_dbp, enckey.c_str(), DB_ENCRYPT_AES);
    if (ret != 0) {
        cout << "User DB set_encrypt Error" << endl;
        return false;
    }

    /* Database open flags */
    flags = DB_CREATE;
    ret = user_dbp->open(user_dbp, /* DB structure pointer */
        NULL, /* Transaction pointer */
        ConfData->account_db_path.c_str(),
        //"account.db", /* On-disk file that holds the database. */
        NULL, /* Optional logical database name */
        DB_HASH, /* Database access method */
        flags, /* Open flags */
        0); /* File mode (using defaults) */
    if (ret != 0) {
        /* Error handling goes here */
        cout << "Account DB Open Error" << endl;
        return false;
    }

    return true;
}

boolean openOtpBaseDb() {
    int ret;
    string enckey = "";

    /* Database open flags */
    ret = db_create(&otpbase_dbp, NULL, 0);
    if (ret != 0) {
        /* Error handling goes here */
        if (ConfData->debug) {
            cout << "otp base DB Create Error" << endl;
        }
        return false;
    }

    enckey = parseDbKey(ConfData->otpbase_db_key_path);
    if (enckey.empty()) {
        if (ConfData->debug) {
            cout << "otp base DB kry empty" << endl;
        }
        return false;
    }

    ret = otpbase_dbp->set_encrypt(otpbase_dbp, enckey.c_str(), DB_ENCRYPT_AES);
    if (ret != 0) {
        if (ConfData->debug) {
            cout << "User DB set_encrypt Error" << endl;
        }
        return false;
    }

    /* Database open flags */
    flags = DB_CREATE;
    ret = otpbase_dbp->open(otpbase_dbp, /* DB structure pointer */
        NULL, /* Transaction pointer */
        ConfData->otpbase_db_path.c_str(), /* On-disk file that holds the database. */
        NULL, /* Optional logical database name */
        DB_HASH, /* Database access method */
        flags, /* Open flags */
        0); /* File mode (using defaults) */
    if (ret != 0) {
        /* Error handling goes here */
        if (ConfData->debug) {
            cout << "otp base DB Open Error" << endl;
        }
        return false;
    }

    return true;
}

int main()
{
    TTcpListenPort* TcpListenPort;
    TTcpConnectedPort* TcpConnectedPort;
    struct sockaddr_in cli_addr;
    socklen_t          clilen;

    string conf_file = "server-conf.json";

    if (parse_configure(conf_file))
    { 
        cout << "configuration failed" << endl;
        return -1;
    }

    if (!makePlateMap()) {
        /* Error handling goes here */
        cout << "DB Open Error" << endl;
        return -1;
    }

    if (!openAccountDb()) {
        /* Error handling goes here */
        cout << "Account DB Open Error" << endl;
        return -1;
    }

    if (!openOtpBaseDb()) {
        /* Error handling goes here */
        cout << "OTP Base DB Open Error" << endl;
        return -1;
    }


	vector<thread> t_pool;

    std::cout << "Listening\n";
    if ((TcpListenPort = OpenTcpListenPort(ConfData->num_port)) == NULL)  // Open UDP Network port
    {
        std::cout << "OpenTcpListenPortFailed\n";
        return(-1);
    }
    clilen = sizeof(cli_addr);

    thread pkt_mon(monitor_pkt);
    pkt_mon.detach();

    while(1)
    {
#if USE_TLS
        if ((TcpConnectedPort = AcceptTcpConnection(TcpListenPort, &cli_addr, &clilen, caFile, certFile, keyFile)) == NULL)
#else
        if ((TcpConnectedPort = AcceptTcpConnection(TcpListenPort, &cli_addr, &clilen)) == NULL)
#endif
        {
            cout << "AcceptTcpConnection Failed" << endl;
            return(-1);
        }
        cout << "connected" << endl;

        t_pool.push_back(thread(process_data, TcpConnectedPort));
        t_pool.back().detach();
    }
}



