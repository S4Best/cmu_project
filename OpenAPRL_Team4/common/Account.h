
#include <string>
#include <stdint.h>
#include <vector>

#ifdef USE_STD_NAMESPACE
using std::string;
#endif


namespace account
{
  class AccountResult
  {
    public:
      AccountResult() 
      {
          userId = "";
          password = "";
          otpKey = "";
      };
      virtual ~AccountResult() {};

      std::string userId;
      std::string password;
      std::string otpKey;
  };

  class AccountRequest
  {
    public:
      AccountRequest() 
      {
          userId = "";
          password = "";
          otp = "";
      };
      virtual ~AccountRequest() {};

      std::string userId;
      std::string password;
      std::string otp;
  };

  class AccountOtpBase
  {
  public:
      AccountOtpBase()
      {
          otpKey = "";
          otpBase = "";
      };
      virtual ~AccountOtpBase() {};

      std::string otpKey;
      std::string otpBase;
  };

  class  Account
  {

    public:
      Account();
      virtual ~Account();
	  
      static std::string convertToJsonStringByAccountResult(const AccountResult result);

      static AccountResult getAccountResultByJsonString(const char* resultJson);

	  static std::string convertToJsonStringByAccountRequest(const AccountRequest request);

	  static AccountRequest getAccountRequestByJsonString(const char* requestJson);

      static AccountOtpBase getAccountOtpBaseByJsonString(const char* otpJson);
     
  };

}
