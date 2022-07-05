
#include "Account.h"
#include "cjson.h"

using namespace std;

namespace account
{

  Account::Account()
  {
  }

  Account::~Account()
  {
  }

  std::string Account::convertToJsonStringByAccountResult(const AccountResult result) {

    cJSON *cjson;
    cjson = cJSON_CreateObject();

    char accountId[1024];
    char accountPw[1024];
    char accountOtpKey[1024];

    strncpy_s(accountId, sizeof(accountId), result.userId.c_str(), result.userId.size());
    strncpy_s(accountPw, sizeof(accountPw), result.password.c_str(), result.password.size());
    strncpy_s(accountOtpKey, sizeof(accountOtpKey), result.otpKey.c_str(), result.otpKey.size());

    cJSON_AddStringToObject(cjson, "userId", accountId);
    cJSON_AddStringToObject(cjson, "password", accountPw);
    cJSON_AddStringToObject(cjson, "optKey", accountOtpKey);

    char *out;
    out=cJSON_PrintUnformatted(cjson);


    cJSON_Delete(cjson);

    std::string accountResultStr(out);

    free(out);
    return accountResultStr;
  }

  AccountResult Account::getAccountResultByJsonString(const char* json) {

    AccountResult accountResult;

    cJSON* cjson= cJSON_Parse(json);

    if (cjson == NULL) {
        return accountResult;
    }

    if (cJSON_GetObjectItem(cjson, "userId") != NULL) {
        accountResult.userId = std::string(cJSON_GetObjectItem(cjson, "userId")->valuestring);
    }

    if (cJSON_GetObjectItem(cjson, "password") != NULL) {
        accountResult.password = std::string(cJSON_GetObjectItem(cjson, "password")->valuestring);
    }

    if (cJSON_GetObjectItem(cjson, "otpKey") != NULL) {
        accountResult.otpKey = std::string(cJSON_GetObjectItem(cjson, "otpKey")->valuestring);
    }

    cJSON_Delete(cjson);

    return accountResult;
  }

  std::string Account::convertToJsonStringByAccountRequest(const AccountRequest request) {
  
    cJSON *cjson;
    cjson = cJSON_CreateObject();

    char userId[1024];
    char userPw[1024];
    char userOtp[1024];

    strncpy_s(userId, sizeof(userId), request.userId.c_str(), request.userId.size());
    strncpy_s(userPw, sizeof(userPw), request.password.c_str(), request.password.size());
    strncpy_s(userOtp, sizeof(userOtp), request.otp.c_str(), request.otp.size());

    cJSON_AddStringToObject(cjson, "userId", userId);
    cJSON_AddStringToObject(cjson, "password", userPw);
    cJSON_AddStringToObject(cjson, "otp", userOtp);

    char *out;
    out=cJSON_PrintUnformatted(cjson);

    cJSON_Delete(cjson);

    std::string accountRequestStr(out);

    free(out);
    return accountRequestStr;
  }

  AccountRequest Account::getAccountRequestByJsonString(const char* json) {

    AccountRequest accountRequest;

    cJSON* cjson= cJSON_Parse(json);

    if (cjson == NULL) {
        return accountRequest;
    }

    if (cJSON_GetObjectItem(cjson, "userId") != NULL) {
        accountRequest.userId = std::string(cJSON_GetObjectItem(cjson, "userId")->valuestring);
    }

    if (cJSON_GetObjectItem(cjson, "password") != NULL) {
        accountRequest.password = std::string(cJSON_GetObjectItem(cjson, "password")->valuestring);
    }

    if (cJSON_GetObjectItem(cjson, "otp") != NULL) {
        accountRequest.otp = std::string(cJSON_GetObjectItem(cjson, "otp")->valuestring);
    }

    cJSON_Delete(cjson);

    return accountRequest;
  }


  AccountOtpBase Account::getAccountOtpBaseByJsonString(const char* json) {

      AccountOtpBase accountOtpBase;

      cJSON* cjson = cJSON_Parse(json);

      if (cjson == NULL) {
          return accountOtpBase;
      }

      if (cJSON_GetObjectItem(cjson, "otpKey") != NULL) {
          accountOtpBase.otpKey = std::string(cJSON_GetObjectItem(cjson, "otpKey")->valuestring);
      }

      if (cJSON_GetObjectItem(cjson, "otpBase") != NULL) {
          accountOtpBase.otpBase = std::string(cJSON_GetObjectItem(cjson, "otpBase")->valuestring);
      }

      cJSON_Delete(cjson);

      return accountOtpBase;
  }


  bool checkEmptyString(const string &str) {
	return str.size() == 0;
  }

}

