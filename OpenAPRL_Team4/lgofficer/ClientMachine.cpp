#include "pch.h"
#include "WinUser.h"
#include "ClientMachine.h"
#include "lgdemo_run.h"
#include "Resource.h"
#include "Account.h"
#include "Logger.h"
#include "sechelper.h"

#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <future>
#include <condition_variable>
#include <regex>
#include <fstream>
#include "json/json.h"
#include <fcntl.h>

using namespace std;
using namespace account;

CClientMachine* cm;

regex RegexOtp("^[0-9]{6}$");
regex RegexUserId("^[a-zA-Z0-9_-]{8,20}$");
//Minimum eight characters, at least one uppercase letter, one lowercase letter, one numberand one special character
regex RegexPassword("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,20}$");

struct state_manage_s state_table[LGC_ST_MAX] =
{
    {_T("Initializing..."),NULL /* LGC_ST_INITIALIZING */   },
    {_T("Connecting..."),  NULL /* LGC_ST_CONNECTING */     },
    {_T("Need to Auth"),   NULL /* LGC_ST_CONNECTION_DONE */},
    {_T("Wait...(10sec)"), NULL /* LGC_ST_PENDING */        },
    {_T("Authenticating"), NULL /* LGC_ST_AUTHENTICATING */ },
    {_T("Ready"),          NULL /* LGC_ST_SVC_READY */      },
    {_T("Running"),        NULL /* LGC_ST_SVC_RUNNING */    },
    {_T("Disconnect!"),    NULL /* LGC_ST_DISCONNECT */     },
    {_T("Disconnected"),   NULL /* LGC_ST_DISCONNECTED */   },
    {_T("Exit..."),        NULL /* LGC_ST_DESTROY */        },
};

void printMsg(int flag, std::string msg)
{
    if (cm)
    {
        CString cstr(msg.c_str());
        if (flag & mtype::mMsg)
        {
            cm->getApp()->setMsg(cstr);
        }
        if (flag & mtype::mAlert)
        {
            //TODO alert to be replaced
            cm->getApp()->setMsg(cstr);
        }
    }
}

void sendRecognizedLicence(char* lic, size_t lic_len, int frameno)
{
    // sendpacket with license number
    try
    {
        if (cm && lic)
        {
            if (lic_len > MAX_PAYLOAD_LEN)
            {
                MSG(mtype::mErrMsg, "%s : invalid input", __FUNCTION__);
                return;
            }

            char buf[MAX_PAYLOAD_LEN+1] = { 0, };
            snprintf(buf, sizeof(buf), "%s#%d", lic, frameno);
            cm->sendPacket(LGC_CMD_LIC_QUERY, strnlen(buf, sizeof(buf)), (unsigned char*)buf);
        }
        else
        {
            MSG(mtype::mErrMsg, "%s : invalid input", __FUNCTION__);
        }
    }
    catch (std::exception& e) {
        MSG(mtype::mErrMsg, "sendRecognizedLicence exception is occurred:" + std::string(e.what()));
    }
}

bool checkValidState()
{
    bool isValid = FALSE;

    try
    {
        if (cm &&
            cm->getCliStatus() == LGC_ST_SVC_RUNNING &&
            cm->isValidTCPPort())
        {
            isValid = TRUE;
        }
    }
    catch (std::exception& e) {
        MSG(mtype::mErrMsg, "checkValidState exception is occurred:" + std::string(e.what()));
    }

    return isValid;
}

void informFromDemoRun(info_type_e info_t, char* buf, size_t buf_len)
{
    try
    {
        if (cm)
        {
            //MSG(mtype::mMsgWithConsole, "comming inform from demo run");
            switch (info_t)
            {
                case INFO_T_END:
                {
                    if(cm->getCliStatus() == LGC_ST_SVC_RUNNING)
                    {
                        /* end of lgdemo run normally */
                        MSG(mtype::mMsgWithConsole, "LGdemo is ended naturally, set status to ready");
                        cm->setCliStatus(LGC_ST_SVC_READY);
                    }
                    break;
                }
                case INFO_T_FRAME:
                {
                    if (buf == NULL || buf_len == 0)
                    {
                        MSG(mtype::mMsgWithConsole, "There is no data");
                        return;;
                    }
                    break;
                }
                default:
                    /* never enter here */
                    break;
            }
        }
    }
    catch (std::exception& e) {
        MSG(mtype::mErrMsg, "informFromDemoRun exception is occurred:" + std::string(e.what()));
    }
}

void pushRecogImage(cv::Mat frame, std::string lic_num, int frameno)
{
    try
    {
        if (cm)
        {
            CFrameInfo f(frame, lic_num, frameno);
            cm->frameEnQ(f);
        }
    }
    catch (std::exception& e) {
        MSG(mtype::mErrMsg, "pushRecogImage exception is occurred:" + std::string(e.what()));
    }
}

bool CClientMachine::getExitFlag()
{
    bool flag;
    this->mtx_main.lock();
    flag = this->exitFlag;
    this->mtx_main.unlock();
    return flag;
}

CClientMachine::CClientMachine(ClgofficerDlg* appPtr)
    : stateChanged(false), exitFlag(false), cur_st(LGC_ST_INITIALIZING), prev_st(LGC_ST_INITIALIZING)
    , TcpConnectedPort(NULL)
    , host_ip("127.0.0.1"), host_port("2222")
    , _id{}, _pw{}, _otp{}, _id_len(0), _pw_len(0), _otp_len(0)
    , CertFile(NULL), CAFile(NULL), KeyFile(NULL)
    , fp(NULL)
{
    this->app = appPtr;
    this->activeWnd = CWnd::GetActiveWindow();
    cm = this;
    this->frameQ.clear();

    Logger::getInstance().setPrintMsgFunc(printMsg);
    this->clearUserCredential();
    this->setCliStatus(LGC_ST_INITIALIZING);

    this->getCliSetting();
}

CClientMachine::~CClientMachine()
{
    lgc_state_e curState;
    this->mtx_main.lock();
    curState = this->cur_st;
    this->mtx_main.unlock();

    this->setCliStatus(LGC_ST_DESTROY);

    if (curState == LGC_ST_SVC_RUNNING)
    {
        this->qmtx_.lock();
        this->qwakeup_ = true;
        this->qmtx_.unlock();
        this->qcv_.notify_one();
    }

    if (m_pThread.joinable())
        m_pThread.join();

    if (ptrLgdr)
        ptrLgdr = nullptr;

    this->frameQ.clear();
    this->closeServer();
}

void CClientMachine::getCliSetting()
{
    ifstream stream;
    string conf_path = "client-conf.json";

    /* read .json */
    stream.open(conf_path);
    if (stream.fail())
    {
        MSG(mtype::mMsgWithConsole, "conf file open fai : " + conf_path);
        return;
    }

    Json::Value root;
    stream >> root;

    this->host_ip = root["server_ip"].asString();

    client_cert_path = root["client_cert_path"].asString();
    if (!client_cert_path.empty())
    {
        this->CertFile = client_cert_path.c_str();
    }

    client_key_path = root["client_key_path"].asString();
    if (!client_key_path.empty())
    {
        this->KeyFile = client_key_path.c_str();
    }

    ca_cert_path = root["ca_cert_path"].asString();
    if (!ca_cert_path.empty())
    {
        this->CAFile = ca_cert_path.c_str();
    }
    
    MSG(mtype::mMsgWithConsole, "server-ip : " + this->host_ip);

    stream.close();
    return;
}

void CClientMachine::client_state_machine_thread()
{
    while (1)
    {
        std::unique_lock<std::mutex> lk(cm->mtx_main);
        cm->cv_main.wait(lk, [&] { return cm->stateChanged || cm->exitFlag; });

        if (cm->stateChanged)
        {
            lgc_state_e changed_st = cm->getCliStatus();
            cm->stateChanged = false;
            lk.unlock();

            if (changed_st < LGC_ST_START_IDX || changed_st >= LGC_ST_MAX)
            {
                MSG(mtype::mMsgWithConsole, "invalid state : " + std::to_string(changed_st));
                continue;
            }

            // state desc print on UI
            cm->getApp()->setStateText(state_table[changed_st].state_desc);

            // call state changed handler
            res_e state_func_res = LGC_FAILURE;
            switch (changed_st)
            {
                case LGC_ST_INITIALIZING:
                    MSG(mtype::mMsgWithConsole, "initialization start");
                    state_func_res = cm->state_func_init();
                    if (state_func_res == LGC_SUCCESS)
                    {
                        MSG(mtype::mMsgWithConsole, "initialization done");

                        lk.lock();
                        cm->stateChanged = true;
                        cm->prev_st = cm->cur_st;
                        cm->cur_st = LGC_ST_CONNECTING;
                        lk.unlock();
                    }
                    else
                    {
                        MSG(mtype::mMsgWithConsole, "system malfunction, contact admin");
                        cm->getApp()->setStateText(_T("system malfunction"));
                    }
                    MSG(mtype::mMsgWithConsole, "cipher initialization start");
                    client_cipher_init();
                    MSG(mtype::mMsgWithConsole, "cipher initialization done");
                    break;
                case LGC_ST_CONNECTING:
                    MSG(mtype::mMsgWithConsole, "try to connect with server");
                    state_func_res = cm->state_func_connect();
                    if (state_func_res == LGC_SUCCESS)
                    {
                        MSG(mtype::mMsgWithConsole, "Connection done");

                        lk.lock();
                        cm->stateChanged = true;
                        cm->prev_st = cm->cur_st;
                        cm->cur_st = LGC_ST_CONNECTION_DONE;
                        lk.unlock();
                    }
                    else
                    {
                        MSG(mtype::mMsgWithConsole, "Connection fail, go to pending for 10sec");

                        lk.lock();
                        cm->stateChanged = true;
                        cm->prev_st = cm->cur_st;
                        cm->cur_st = LGC_ST_PENDING;
                        lk.unlock();
                    }
                    break;
                case LGC_ST_PENDING:
                    MSG(mtype::mMsgWithConsole, "call pending, block connection for 10sec");
                    lk.lock();
                    cm->stateChanged = true;
                    cm->prev_st = cm->cur_st;
                    cm->cur_st = LGC_ST_CONNECTING;
                    lk.unlock();
                    cm->state_func_pending();
                    MSG(mtype::mMsgWithConsole, "pending end, try to re-connect with server");

                    break;
                case LGC_ST_CONNECTION_DONE:
                    MSG(mtype::mMsgWithConsole, "authentication is needed");
                    cm->getApp()->setUiEnable(LGC_ST_CONNECTION_DONE);
                    break;
                case LGC_ST_AUTHENTICATING:
                    if (cm->prev_st != LGC_ST_CONNECTION_DONE)
                    {
                        MSG(mtype::mMsgWithConsole, "server connection first, cannot proceed authentication");

                        lk.lock();
                        cm->stateChanged = true;
                        cm->prev_st = cm->cur_st;
                        cm->cur_st = LGC_ST_DISCONNECT;
                        lk.unlock();
                    }
                    else
                    {
                        MSG(mtype::mMsgWithConsole, "try to officer authenticating...");

                        state_func_res = cm->state_func_authentication();
                        if (state_func_res != LGC_SUCCESS)
                        {
                            MSG(mtype::mMsgWithConsole, "authentication request fail");

                            lk.lock();
                            cm->prev_st = LGC_ST_CONNECTION_DONE;
                            cm->cur_st = LGC_ST_CONNECTION_DONE;
                            lk.unlock();
                        }
                    }
                    break;
                case LGC_ST_SVC_READY:
                    cm->getApp()->setUiEnable(LGC_ST_SVC_READY);
                    if (cm->isLgdrRunning())
                    {
                        MSG(mtype::mMsgWithConsole, "stop svc, return to ready");
                        cm->stopLgdr();
                        cm->clearQ();
                    }
                    else
                    {
                        MSG(mtype::mMsgWithConsole, "authentication done, ready for setting and start service");
                    }
                    break;
                case LGC_ST_SVC_RUNNING:
                    cm->getApp()->setUiEnable(LGC_ST_SVC_RUNNING);
                    if (cm->prev_st != LGC_ST_SVC_READY)
                    {
                        MSG(mtype::mMsgWithConsole, "not ready");

                        lk.lock();
                        cm->stateChanged = true;
                        cm->cur_st = cm->prev_st;
                        lk.unlock();
                    }
                    else
                    {
                        MSG(mtype::mMsgWithConsole, "running service...");

                        // call main service function
                        state_func_res = cm->state_func_svc_running();
                    }

                    break;
                case LGC_ST_DISCONNECTED:
                {
                    // connection recvery requirement
                    MSG(mtype::mMsgWithConsole, "disconnected... try to re-connect with server");
                    if (cm->isLgdrRunning())
                    {
                        MSG(mtype::mMsgWithConsole, "stop svc");
                        cm->stopLgdr();
                    }
                    cm->closeServer();
                    cm->getApp()->setUiEnable(LGC_ST_DISCONNECTED);

                    int cnt = 0;
                    do {
                        state_func_res = cm->state_func_connect();
                        if (state_func_res == LGC_SUCCESS)
                        {
                            // state handling, if re-connected, go to connection done
                            // auth is needed
                            lk.lock();
                            cm->stateChanged = true;
                            cm->prev_st = cm->cur_st;
                            cm->cur_st = LGC_ST_CONNECTION_DONE;
                            lk.unlock();
                        }
                        else
                        {
                            // retry count is 5, interval is 1sec --> 10sec
                            if (cnt < 10)
                            {
                                cnt++;
                                MSG(mtype::mMsgWithConsole, "Fail to re-connect, retry:" + std::to_string(cnt));
                                //std::this_thread::sleep_for(std::chrono::milliseconds(1000 * 1));
                                Sleep(1000);
                                continue;
                            }

                            // when trying re-connect is failed, goto pending and
                            // try connect again
                            MSG(mtype::mMsgWithConsole, "Fail to re-connect, go to pending state");

                            lk.lock();
                            cm->stateChanged = true;
                            cm->prev_st = cm->cur_st;
                            cm->cur_st = LGC_ST_PENDING;
                            lk.unlock();
                        }
                        break;
                    } while (1);
                    break;
                }
                case LGC_ST_DISCONNECT: /* for test or exit only */
                    MSG(mtype::mMsgWithConsole, "disconnect!");
                    if (cm->isLgdrRunning())
                    {
                        MSG(mtype::mMsgWithConsole, "stop svc");
                        cm->stopLgdr();
                    }

                    cm->closeServer();
                    cm->getApp()->setUiEnable(LGC_ST_DISCONNECT);

                    lk.lock();
                    cm->stateChanged = true;
                    cm->prev_st = cm->cur_st;
                    cm->cur_st = LGC_ST_PENDING;
                    lk.unlock();

                    break;

                case LGC_ST_DESTROY:
                    MSG(mtype::mMsgWithConsole, "end service...");
                    if (cm->isLgdrRunning())
                    {
                        MSG(mtype::mMsgWithConsole, "stop");
                        cm->stopLgdr();
                    }

                    lk.lock();
                    cm->exitFlag = true;
                    lk.unlock();
                    break;
                default:
                    /* do not enter here */
                    break;
            }
            continue;
        }
        else if (cm->exitFlag)
        {
            cm->exitFlag = false;
            MSG(mtype::mMsgWithConsole, "thread... request stop");
            lk.unlock();
            break;
        }
    }
    MSG(mtype::mMsgWithConsole, "thread... break done, destroy");
}

void CClientMachine::run(void)
{
    m_pThread = std::thread([&]()
    {
        client_state_machine_thread();
    });
}

res_e CClientMachine::setCliStatus(lgc_state_e st)
{
    lgc_state_e prevState;

    //MSG(mtype::mMsg, "state changed prev : %d, cur : %d", this->prev_st, this->cur_st);

    this->mtx_main.lock();
    prevState = this->cur_st;
    this->prev_st = this->cur_st;
    this->cur_st = st;
    this->stateChanged = true;
    if(st == LGC_ST_DESTROY)
        this->exitFlag = true;
    this->mtx_main.unlock();
    this->cv_main.notify_one();

    if (prevState == LGC_ST_SVC_RUNNING)
    {
        this->qmtx_.lock();
        this->qwakeup_ = true;
        this->qmtx_.unlock();
        this->qcv_.notify_one();
    }

    return LGC_SUCCESS;
}

res_e CClientMachine::state_func_init()
{
    this->ptrLgdr = shared_ptr<LGDemoRun>(new LGDemoRun(sendRecognizedLicence, checkValidState));
    if (this->ptrLgdr == nullptr)
    {
        MSG(mtype::mMsgWithConsole, "fail to gen lgdemo");
        return LGC_FAILURE;
    }

    this->ptrLgdr->setInformFunc(informFromDemoRun);
    this->ptrLgdr->setPushRecgFunc(pushRecogImage);

    return LGC_SUCCESS;
}

res_e CClientMachine::state_func_pending(void)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(1000 * 1 * 10));
    return LGC_SUCCESS;
}

res_e CClientMachine::state_func_connect(void)
{
    // connect server
    return this->connectServer();
}

res_e CClientMachine::connectServer(void)
{
#ifdef USE_TLS
    if ((TcpConnectedPort = OpenTcpConnection(host_ip.c_str(), host_port.c_str(), CAFile, CertFile, KeyFile)) == NULL)
#else
    if ((TcpConnectedPort = OpenTcpConnection(host_ip.c_str(), host_port.c_str())) == NULL)
#endif
    {
        MSG(mtype::mMsgWithConsole, "Connection Failed");
        return LGC_FAILURE;
    }
    else
    {
        MSG(mtype::mMsgWithConsole, "Connected");

        // set sock non-blocking mode
        if (0 != setNonBlockingSock(TcpConnectedPort))
        {
            MSG(mtype::mMsgWithConsole, "fail to set nobio sock");
            return LGC_FAILURE;
        }

        // start server socket listener
        t_server_listener = std::thread([&]()
        {
            startServerListener();
        });
    }

    return LGC_SUCCESS;
}

res_e CClientMachine::closeServer(void)
{
    MSG(mtype::mMsgWithConsole, "Disconnection");
    if (TcpConnectedPort)
    {
        /* stop server listener*/
        this->stopServerListener();

        CloseTcpConnectedPort(&TcpConnectedPort);
        TcpConnectedPort = NULL;

        return LGC_SUCCESS;
    }
    else
    {
        MSG(mtype::mMsgWithConsole, "Already disconnected");
        return LGC_SUCCESS;
    }
}

void CClientMachine::clearUserCredential()
{
    memset(this->_id, 0x00, sizeof(this->_id));
    memset(this->_pw, 0x00, sizeof(this->_pw));
    memset(this->_otp, 0x00, sizeof(this->_otp));

    _id_len = 0;
    _pw_len = 0;
    _otp_len = 0;
}

res_e CClientMachine::setUserCredential(
    char* id, unsigned short id_len,
    char* pw, unsigned short pw_len,
    char* otp, unsigned short otp_len
)
{
    smatch m;

#ifndef LGC_TEST_WITHOUT_AUTH
    if (id_len > MAX_USR_ID_LENGTH || id_len < MIN_USR_ID_LENGTH ||
        pw_len > MAX_USR_PW_LENGTH || pw_len < MIN_USR_PW_LENGTH ||
        otp_len != MAX_USR_OTP_LENGTH)
    {
        return LGC_FAILURE;
    }
#endif

    if (id == NULL || pw == NULL || otp == NULL)
    {
        return LGC_FAILURE;
    }

    string userID = id;
    string userPw = pw;
    string userOtp = otp;

#ifndef LGC_TEST_WITHOUT_AUTH
    if (!regex_match(userID, m, RegexUserId)) {
        MSG(mtype::mMsgWithConsole, "Only uppercase and lowercase letters and numbers are allowed for ID.");
        return LGC_FAILURE;
    }

    if (!regex_match(userPw, RegexPassword)) {
        MSG(mtype::mMsgWithConsole, "password must contain at least one uppercase and lowercase letter and number, special character.");
        return LGC_FAILURE;
    }

    if (!regex_match(userOtp, RegexOtp)) {
        MSG(mtype::mMsgWithConsole, "Only numbers are allowed for OTP.");
        return LGC_FAILURE;
    }
#endif

    this->clearUserCredential();

    this->_id_len = id_len;
    memcpy(this->_id, id, id_len);

    this->_pw_len = pw_len;
    memcpy(this->_pw, pw, pw_len);

    this->_otp_len = otp_len;
    memcpy(this->_otp, otp, otp_len);

    MSG(mtype::mDebug, "id:%s, id_len:%u", id, id_len);
    MSG(mtype::mDebug, "pw:%s, pw_len:%u", pw, pw_len);
    MSG(mtype::mDebug, "otp:%s, otp_len:%u", otp, otp_len);

    return LGC_SUCCESS;
}

res_e CClientMachine::state_func_authentication()
{
    res_e res = LGC_SUCCESS;

    // TODO[Auth] send user credential
    // temporary code
    AccountRequest accountRequest;

    char* userId = this->_id;
    char* userPw = this->_pw;
    char* userOtp = this->_otp;

    if (userId == 0 || userPw == 0 || userOtp == 0) {
        MSG(mtype::mMsgWithConsole, "fail to login due to invalid info");
        return LGC_FAILURE;
    }

    accountRequest.userId = userId;
    accountRequest.password = userPw;
    accountRequest.otp = userOtp;

    string requestJsonStr = Account::convertToJsonStringByAccountRequest(accountRequest);
    res = sendPacket(LGC_CMD_LOGIN, (unsigned int)requestJsonStr.length(), (unsigned char*)requestJsonStr.c_str());
    if (res != LGC_SUCCESS) {
        MSG(mtype::mMsgWithConsole, "fail to login sendPacket");
    }

    return res;
}

res_e CClientMachine::state_func_svc_running()
{
    res_e res = LGC_SUCCESS;

    ptrLgdr->run(this->demoMode);

    if (fp)
    {
        fclose(fp);
        fp = NULL;
    }

    if (fopen_s(&fp, FILE_ALERT_LOG, "a+") != 0)
    {
        MSG(mtype::mErrMsg, "fail to open alert meesage log file");
    }

    return res;
}

void CClientMachine::setDemoMode(struct demoMode_s dm)
{
    this->demoMode = dm;
}

bool CClientMachine::isLgdrRunning()
{
    return ptrLgdr && ptrLgdr->isStarted();
}

void CClientMachine::stopLgdr()
{
    ptrLgdr->stop();

    if (fp)
    {
        fclose(fp);
        fp = NULL;
    }
}

/* net */
res_e CClientMachine::sendPacket(lgc_cmd_e cmd, size_t payload_len, unsigned char* payload)
{
    if (!payload)
    {
        MSG(mtype::mMsgWithConsole, "sendPacket fail - invalid arguemnt");
        return LGC_FAILURE;
    }
    if (!TcpConnectedPort)
    {
        MSG(mtype::mMsgWithConsole, "sendPacket fail - None connection");
        return LGC_FAILURE;
    }

    CString cstr;
    ssize_t result;
    int SendMsgHdr[2] = { 0, };
    unsigned int payLen = (unsigned int)payload_len + 1; // plus NULL

    SendMsgHdr[0] = htons(cmd);
    SendMsgHdr[1] = htons(payLen);

    result = WriteDataTcp(TcpConnectedPort, (unsigned char*)SendMsgHdr, sizeof(SendMsgHdr));
    if (result != sizeof(SendMsgHdr))
    {
        /* never enter here */
        MSG(mtype::mMsgWithConsole, "WriteDataTcp malfuction : sended=" + std::to_string(result) + ", expected=" + std::to_string(sizeof(SendMsgHdr)));
        return LGC_FAILURE;
    }

    result = WriteDataTcp(TcpConnectedPort, payload, payLen);
    if (result != payLen)
    {
        /* never enter here */
        MSG(mtype::mMsgWithConsole, "WriteDataTcp malfuction : sended=" + std::to_string(result) + ", expected=" + std::to_string(payload_len));
        return LGC_FAILURE;
    }

    MSG(mtype::mDebug, "sent(" + std::to_string(payLen) + ") -> " + std::string((char*)payload));

    return LGC_SUCCESS;
}

void CClientMachine::startServerListener()
{
    MSG(mtype::mMsgWithConsole, "start server listener");
    int sslfd;

    sk_mtx.lock();
    this->sk_stoppable = FALSE;
    sk_mtx.unlock();

    ResponseMode GetResponseMode = ResponseMode::ReadingHeader;
    int RespHdrNumBytes[2] = { 0, };
    char ResponseBuffer[2048] = { 0, };
    ssize_t BytesNeeded = sizeof(RespHdrNumBytes);
	ssize_t BytesRemaind = 0;
	
#if USE_TLS
    if (this->TcpConnectedPort->isSsl) {
        sslfd = SSL_get_fd(this->TcpConnectedPort->ssl);
        if (sslfd < 0) {
            printf("SSL_get_fd failed\n");
        }
    }
    else
    {
        sslfd = (int)this->TcpConnectedPort->ConnectedFd;
    }
#else
    sslfd = (int)this->TcpConnectedPort->ConnectedFd;
#endif

    while (!getSkStoppable())
    {
        int skfd = sslfd;
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(skfd, &readSet);

        timeval tval{ 2, 0 }; /* timeout 2 sec */

        int totalSocketCount = select(skfd+1, &readSet, nullptr, nullptr, &tval);

        if (totalSocketCount > 0)
        {
            //MSG(mtype::mMsgWithConsole, "select evt");
            if (FD_ISSET(skfd, &readSet))
            {
                int iResult;
                memset(ResponseBuffer, 0x00, sizeof(ResponseBuffer));
#if USE_TLS
                if(this->TcpConnectedPort->isSsl) {
                    iResult = SSL_read(this->TcpConnectedPort->ssl, ResponseBuffer, sizeof(ResponseBuffer));
                }
                else {
                    iResult = recv(skfd, ResponseBuffer, sizeof(ResponseBuffer), 0);
                }
#else
                iResult = recv(skfd, ResponseBuffer, sizeof(ResponseBuffer), 0);
#endif
                if (iResult > 0)
                {
                    printf("Bytes received: %d\n", iResult);

                    // packet hadnling
                    BytesRemaind = iResult;
                    if (GetResponseMode == ResponseMode::ReadingHeader)
                    {
                        if (BytesRemaind >= BytesNeeded)
                        {
                            BytesRemaind -= BytesNeeded;
                            memcpy(RespHdrNumBytes, ResponseBuffer, sizeof(RespHdrNumBytes));
                            RespHdrNumBytes[0] = ntohs(RespHdrNumBytes[0]);
                            RespHdrNumBytes[1] = ntohs(RespHdrNumBytes[1]);
                            GetResponseMode = ResponseMode::ReadingMsg;
                            BytesNeeded = RespHdrNumBytes[1];
                            printf("Response> Header cmd:%d, payload_len:%d\n", RespHdrNumBytes[0], RespHdrNumBytes[1]);
                            printf("BytesRemaind : %d\n", (int)BytesRemaind);
                            if (BytesRemaind != 0 )
                            {
                                if (BytesRemaind == BytesNeeded)
                                {
                                    MSG(mtype::mMsgWithConsole, "[Header + Data]");
                                    printf("Response> %s\n", ResponseBuffer + sizeof(RespHdrNumBytes));
                                    GetResponseMode = ResponseMode::ReadingHeader;
                                    BytesNeeded = sizeof(RespHdrNumBytes);
                                    recvPacketHandler(RespHdrNumBytes[0], RespHdrNumBytes[1], ResponseBuffer + sizeof(RespHdrNumBytes));
                                }
                                else
                                {
                                    /* never enter here */
                                    printf("################## NEVER ENTER HERE!!!! (1) ##################\n");
                                }
                            }
                        }
                        else
                        {
                            /* never enter here */
                            printf("################## NEVER ENTER HERE!!!! (2) ##################\n");
                        }
                    }
                    else if (GetResponseMode == ResponseMode::ReadingMsg)
                    {
                        if (BytesRemaind == BytesNeeded)
                        {
                            printf("Response> %s\n", ResponseBuffer);
                            GetResponseMode = ResponseMode::ReadingHeader;
                            BytesNeeded = sizeof(RespHdrNumBytes);
                            recvPacketHandler(RespHdrNumBytes[0], RespHdrNumBytes[1], ResponseBuffer);
                        }
                        else
                        {
                            /* never enter here */
                            printf("################## NEVER ENTER HERE!!!! (3) ##################\n");
                        }
                    }
                }
                else if (iResult == 0)
                {
                    MSG(mtype::mMsgWithConsole, "Connection closed, noramlly\n");
                    this->setCliStatus(LGC_ST_DISCONNECTED);
                    break;
                }
                else
                {
                    int error_num = WSAGetLastError();
                    if (error_num == WSAEWOULDBLOCK)
                    {
                        printf("WSAEWOULDBLOCK\n");
                    }
                    else if (error_num == WSAECONNRESET)
                    {
                        MSG(mtype::mMsgWithConsole, "Connection closed, WSAECONNRESET\n");
                        this->setCliStatus(LGC_ST_DISCONNECTED);
                        break;
                    }
                    else
                    {
                        printf("recv failed: %d\n", error_num);
                    }
                }
            }
        }
        else
        {
            //printf("timeout occured\n");
        }
    }

    MSG(mtype::mMsgWithConsole, "end server listener, remote is closed or program will be exited");
}

void CClientMachine::recvPacketHandler(int cmd, int payload_len, char *payload)
{
    MSG(mtype::mDebug, "cmd = " + std::to_string(cmd) + ", len = " + std::to_string(payload_len));

    switch (cmd)
    {
    case LGC_CMD_LOGIN:
        if (this->getCliStatus() == LGC_ST_AUTHENTICATING)
        {
            if (0 == memcmp(payload, "login_000_ok", payload_len))
            {
                MSG(mtype::mMsgWithConsole, "login - success");
                this->setCliStatus(LGC_ST_SVC_READY);
            }
            else
            {
                MSG(mtype::mMsgWithConsole, "login - failure");
                this->setCliStatus(LGC_ST_DISCONNECT);
            }
        }
        else
        {
            MSG(mtype::mMsgWithConsole, "Receive login result, but invalid cur state : " + std::to_string(this->getCliStatus()));
        }
        break;
    case LGC_CMD_LIC_QUERY:
    {
        MSG(mtype::mConsole, "Receive query result! ");
        MSG(mtype::mMsgWithConsole, payload);

        /* is there query request ? in Q */
        if (isQEmpty())
        {
            MSG(mtype::mErrMsg, "there is no queried license number");
            break;
        }

        /* parsing frameno from payload */
        char recievedFrameNoStr[128] = { 0, };
        char recievedFrameNoCnt = 0;
        int foundSharpIdx = -1;
        bool foundMatched = FALSE;
        for (int j = payload_len - 1; j >= 0; j--)
        {
            if( payload[j] == '#' )
            {
                foundSharpIdx = j;
                payload[j] = '\0';
                break;
            }
        }

        if (foundSharpIdx == -1)
        {
            MSG(mtype::mErrMsg, "there is no license number in recieved packet");
            break;
        }
        else
        {
            for (int k = foundSharpIdx+1; k < payload_len; k++)
            {
                if (payload[k] == 0)
                    break;

                recievedFrameNoStr[recievedFrameNoCnt] = payload[k];
                recievedFrameNoCnt++;
            }

            MSG(mtype::mConsole, "parsed frame num : %s(%d)", recievedFrameNoStr, recievedFrameNoCnt);
        }

        /* find matched license number query's frame number */
        while (!isQEmpty())
        {
            CFrameInfo finfo = frameDeQ();
            int fno = finfo.getFrameNo();
            char curFrameNoStr[128] = { 0, };
            snprintf(curFrameNoStr, sizeof(curFrameNoStr), "%d", fno);

            MSG(mtype::mDebugConsole, "parsed frame num : %s(%d) in Q", curFrameNoStr, strnlen(curFrameNoStr, sizeof(curFrameNoStr)));

            if (recievedFrameNoCnt != strnlen(curFrameNoStr, sizeof(curFrameNoStr))
                || 0 != strncmp(recievedFrameNoStr, curFrameNoStr, recievedFrameNoCnt))
            {
                MSG(mtype::mConsole, "this frame no is not matched, (Target:%s, Q:%s) continue", recievedFrameNoStr, curFrameNoStr);
                continue;
            }

            foundMatched = TRUE;

            cv::Mat f = finfo.getFrame();

            /* rendering */
            this->getApp()->DrawImage(f);

            break;
        }

        if (!foundMatched)
        {
            MSG(mtype::mErrMsg, "there is no qeuried license number in Q");
            break;
        }

        CString cstr(payload);
        this->getApp()->setAlertText(AlertT::mViolation, cstr);

        size_t written = 0;
        size_t remain = strnlen(payload, MAX_PAYLOAD_LEN);
        do {
            written += fwrite(payload, 1, remain, fp);
            remain -= written;
        } while (written < sizeof(payload));
        fwrite("\n\n", 1, 2, fp);

        break;
    }
    default:
        MSG(mtype::mMsgWithConsole, "invalid cmd");
        break;
    }
}

bool CClientMachine::getSkStoppable()
{
    bool stop_flag = FALSE;
    sk_mtx.lock();
    stop_flag = this->sk_stoppable;
    sk_mtx.unlock();

    return stop_flag;
}

void CClientMachine::stopServerListener()
{
    sk_mtx.lock();
    this->sk_stoppable = TRUE;
    sk_mtx.unlock();

    if (t_server_listener.joinable())
        t_server_listener.join();
}

bool CClientMachine::isValidTCPPort()
{
    if (this->TcpConnectedPort)
        return TRUE;
    else
        return FALSE;
}

void CClientMachine::frameEnQ(CFrameInfo f)
{
    qmtx_.lock();
    try {
        MSG(mtype::mDebugConsole, " [ENQ] msgq before enq size : " + std::to_string(frameQ.size()));
        frameQ.push_back(f);
        qwakeup_ = true;
        MSG(mtype::mDebugConsole, " [ENQ] msgq after enq size : " + std::to_string(frameQ.size()));
    }
    catch (std::exception& e) {
        MSG(mtype::mErrMsg, "dequeue exception is occurred:" + std::string(e.what()));
    }
    qmtx_.unlock();
    qcv_.notify_one();
}

CFrameInfo CClientMachine::frameDeQ()
{
    CFrameInfo f;
    qmtx_.lock();
    try {
        if (!frameQ.empty()) {
            MSG(mtype::mDebugConsole, " [DEQ] msgq before enq size : " + std::to_string(frameQ.size()));
            f = frameQ.front();
            frameQ.pop_front();
            MSG(mtype::mDebugConsole, " [DEQ] msgq after enq size : " + std::to_string(frameQ.size()));
        }
    }
    catch (std::exception& e) {
        MSG(mtype::mErrMsg, "dequeue exception is occurred:" + std::string(e.what()));
    }
    qmtx_.unlock();

    return f;
}

void CClientMachine::qWait() {
    std::unique_lock<std::mutex> lk(qmtx_);
    MSG(mtype::mDebugConsole, " waiting...");
    qcv_.wait(lk, [&] { return qwakeup_ == true; });
    MSG(mtype::mDebugConsole, " waiting end, wakeup");
    qwakeup_ = false;
    lk.unlock();
}

bool CClientMachine::isQEmpty() {
    bool isEmptyFlag = false;
    qmtx_.lock();
    isEmptyFlag = frameQ.empty();
    qmtx_.unlock();
    return isEmptyFlag;
}

void CClientMachine::clearQ()
{
    qmtx_.lock();
    frameQ.clear();
    qmtx_.unlock();
}