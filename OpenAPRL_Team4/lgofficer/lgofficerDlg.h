
// lgofficerDlg.h: 헤더 파일
//

#pragma once

#include "ClientMachine.h"
#include "opencv2/opencv.hpp"
#include <memory>
#include <mutex>
#define UPDATE_MSG  WM_USER + 1

class CClientMachine;
// ClgofficerDlg 대화 상자
class ClgofficerDlg : public CDialogEx
{
private:
	std::shared_ptr<CClientMachine> client;

// 생성입니다.
public:
	ClgofficerDlg(CWnd* pParent = nullptr);	// 표준 생성자입니다.
	~ClgofficerDlg();


// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_LGOFFICER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.


// 구현입니다.
protected:
	CString m_msg;
	CString m_state;
	CEdit cEditMsg;

	std::mutex mtx;

	HICON m_hIcon;

	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	void ui_update();
	LRESULT OnReceivedMsgFromThread(WPARAM w, LPARAM l);

public:
	void setMsg(CString msg);
	void clearMsg();

	void setUiEnable(lgc_state_e st);

	void setStateText(CString state_text);
	void setAlertText(AlertT alertType, CString state_text);
	
	void OnBnClickedButtonLogin();
	void OnBnClickedButtonStart();
	void OnBnClickedButtonDisCon();

	void DrawImage(cv::Mat mat);
	int Mat2CImage(cv::Mat* mat, CImage& img);

	CFont newFont;
	CFont newFont2;
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnClickedButtonEnc();
	afx_msg void OnClickedButtonDec();
	afx_msg void OnClickedStaticFindPw();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void RadioMeida(UINT radio_num);

	Mode getSelectedMedia();
	VideoSaveMode getSelectedSaveMode();
	VideoResolution getSelectedRes();
};
