#ifndef LGDEMO_RUN_H
#define LGDEMO_RUN_H

#include "lgc_type.h"
#include <iostream>
#include <thread>
#include <memory>
#include <mutex>
#include <stdarg.h>
#include "opencv2/opencv.hpp"

typedef void (*lic_send_func)(char* lic, size_t lic_len, int frameno);
typedef bool (*is_valid_state_check_func)(void);
typedef void (*inform_func)(info_type_e info_t, char* buf, size_t buf_len);
typedef void (*push_recog_func)(cv::Mat frame, std::string license_plate_num, int frameno);

class LGDemoRun
{
public:
    LGDemoRun();
    LGDemoRun(lic_send_func lsf, is_valid_state_check_func vcf);
    ~LGDemoRun();

    void sendPrintMsg(std::string msg);
    void sendLicenseNumber(char* lic_num, size_t lic_num_len, int frameno);

    bool isNetValid();
    void setLicSendFunc(lic_send_func lsf) { licSendFuncPtr = lsf; }
    void setInformFunc(inform_func inf) { informFuncPtr = inf; }
    void inform(info_type_e info_t, char* buf, size_t buf_len);

    void setPushRecgFunc(push_recog_func prf) { pushRecognizedFuncPtr = prf; }
    void pushFrame(cv::Mat frame, std::string license_plate_num, int frameno);

    void run(struct demoMode_s dm);
    void stop();
    bool isStoppable();
    bool isStarted();
    void setStarted(bool started);
    void detachThread();

    Mode getMode();
    VideoSaveMode getSaveMode();
    VideoResolution getRes();

protected:
private:
    std::mutex mtx;
    bool stoppable;
    bool started;
    std::thread run_thread;

    struct demoMode_s demoMode;

    lic_send_func licSendFuncPtr;
    is_valid_state_check_func validStateCheckFuncPtr;
    inform_func informFuncPtr;
    push_recog_func pushRecognizedFuncPtr;

};

#endif
