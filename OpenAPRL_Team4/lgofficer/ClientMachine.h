#pragma once

#include <afxwin.h>
#include "lgc_type.h"
#include "lgofficerDlg.h"
#ifdef USE_TLS
#include "NetworkTLS.h"
#else
#include "NetworkTCP.h"
#endif
#include "lgdemo_run.h"
#include <thread>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <deque>

class CFrameInfo {
public :
	CFrameInfo() {}
	CFrameInfo(cv::Mat f, std::string num, int frameno) :
		_frame(f), _lic_num(num), _frameno(frameno) {};
	~CFrameInfo() {}

	cv::Mat _frame;
	std::string _lic_num;
	int _frameno;

	std::string getLicNum() { return _lic_num; }
	cv::Mat getFrame() { return _frame; }
	int getFrameNo() { return _frameno; }
};

class ClgofficerDlg;
class CClientMachine
{
public:
	CClientMachine(ClgofficerDlg* appPtr);
	~CClientMachine();

	void run(void);

	/* getter/setter */
	ClgofficerDlg* getApp() { return app; }
	
	lgc_state_e cur_st;
	lgc_state_e prev_st;
	res_e setCliStatus(lgc_state_e st);
	lgc_state_e getCliStatus() { return cur_st; }

	/* auth */
	res_e setUserCredential(	
		char* id, unsigned short id_len,
		char* pw, unsigned short pw_len,
		char* otp, unsigned short otp_len
	);

	/* for LGDemoRun */
	void setDemoMode(struct demoMode_s dm);
	bool isLgdrRunning();
	void stopLgdr();

	bool exitFlag;
	bool getExitFlag();
	bool stateChanged;
	std::condition_variable cv_main;
	std::mutex mtx_main;
	
	std::thread m_pThread;
	void client_state_machine_thread();

	/* net */
	res_e sendPacket(lgc_cmd_e cmd, size_t payload_len, unsigned char* payload);
	bool isValidTCPPort();

	bool qwakeup_;
	std::mutex qmtx_;
	std::condition_variable qcv_;
	std::deque<CFrameInfo> frameQ;
	void frameEnQ(CFrameInfo f);
	CFrameInfo frameDeQ();
	void qWait();
	bool isQEmpty();
	void clearQ();

	FILE* fp;

private:
	ClgofficerDlg* app;
	CWnd* activeWnd;

	/* net */
	TTcpConnectedPort* TcpConnectedPort;
	std::string host_ip;
	std::string host_port;
	std::thread t_server_listener;
	std::condition_variable sk_cv;
	std::mutex sk_mtx;
	bool sk_stoppable;
	bool sk_started;
	bool getSkStoppable();
	void startServerListener();
	void stopServerListener();
	void recvPacketHandler(int cmd, int payload_len, char* payload);

	void getCliSetting();
	res_e connectServer(void);
	res_e closeServer(void);

	/* auth */
	char _id[MAX_USR_ID_LENGTH+1];
	char _pw[MAX_USR_PW_LENGTH+1];
	char _otp[MAX_USR_OTP_LENGTH+1];
	unsigned short _id_len, _pw_len, _otp_len;
	void clearUserCredential();

	/* for LGDemoRun */
	std::shared_ptr<LGDemoRun> ptrLgdr;
	struct demoMode_s demoMode;

	/* state machine core functions */
	res_e state_func_init(void);
	res_e state_func_pending(void);
	res_e state_func_connect(void);
	res_e state_func_authentication();
	res_e state_func_svc_running(void);

	/* cert setting */
	std::string client_cert_path;
	std::string client_key_path;
	std::string ca_cert_path;
	const char *CertFile;
	const char *KeyFile;
	const char *CAFile;
};

struct state_manage_s {
	CString state_desc;
	res_e (CClientMachine::* state_func)(void); /* need to check. dosen't work */
};

