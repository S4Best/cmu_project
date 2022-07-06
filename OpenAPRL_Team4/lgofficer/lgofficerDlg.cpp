
// lgofficerDlg.cpp: 구현 파일
//

#include "lgdemo_run.h"
#include "pch.h"
#include "framework.h"
#include "lgofficer.h"
#include "lgofficerDlg.h"
#include "afxdialogex.h"
#include "sechelper.h"
#include <string>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;


// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// ClgofficerDlg 대화 상자


#include <iostream>
using namespace std;
ClgofficerDlg::ClgofficerDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_LGOFFICER_DIALOG, pParent)
	, m_msg(_T(""))
	, m_state(_T(""))
	, client(nullptr)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	this->client = std::make_shared<CClientMachine>(this);

	std::cout << "start officer" << std::endl;
	this->client->run();

}

ClgofficerDlg::~ClgofficerDlg()
{
	if (this->client)
	{
		this->client = nullptr;
	}
}

void ClgofficerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_MSG, m_msg);
	DDX_Text(pDX, IDC_EDIT_STATE, m_state);
	DDX_Control(pDX, IDC_EDIT_MSG, cEditMsg);
}

BEGIN_MESSAGE_MAP(ClgofficerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(UPDATE_MSG, OnReceivedMsgFromThread)
	ON_BN_CLICKED(IDC_BUTTON_LOGIN, &ClgofficerDlg::OnBnClickedButtonLogin)
	ON_BN_CLICKED(IDC_BUTTON_START, &ClgofficerDlg::OnBnClickedButtonStart)

	ON_BN_CLICKED(IDC_BUTTON_ENC, &ClgofficerDlg::OnClickedButtonEnc)
	ON_BN_CLICKED(IDC_BUTTON_DEC, &ClgofficerDlg::OnClickedButtonDec)
	ON_STN_CLICKED(IDC_STATIC_FIND_PW, &ClgofficerDlg::OnClickedStaticFindPw)
	ON_WM_CTLCOLOR()

	ON_CONTROL_RANGE(BN_CLICKED, IDC_RADIO_MEIDA_LIVE, IDC_RADIO_MEIDA_IMAGE, &ClgofficerDlg::RadioMeida)
END_MESSAGE_MAP()


// ClgofficerDlg 메시지 처리기

BOOL ClgofficerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	GetDlgItem(IDC_STATIC_ALERT)->SetWindowText(_T(""));
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO_RES_480P)->EnableWindow(FALSE);
	GetDlgItem(IDC_RADIO_RES_720P)->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_RADIO_MEIDA_PLAYBACK))->SetCheck(true);
	((CButton*)GetDlgItem(IDC_RADIO_SAVE_Y))->SetCheck(true);

	CFont* currentFont = this->GetFont();
	LOGFONT logFont;
	currentFont->GetLogFont(&logFont);
	logFont.lfHeight = 18;
	logFont.lfWeight = FW_BOLD;
	this->newFont.CreateFontIndirectW(&logFont);
	this->GetDlgItem(IDC_STATIC_ALERT)->SetFont(&this->newFont);

	LOGFONT logFont2;
	currentFont->GetLogFont(&logFont2);
	logFont2.lfUnderline = TRUE;
	this->newFont2.CreateFontIndirectW(&logFont2);
	this->GetDlgItem(IDC_STATIC_FIND_PW)->SetFont(&this->newFont2);

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

void ClgofficerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 애플리케이션의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void ClgofficerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();

		CImage carImg;
		if (SUCCEEDED(carImg.Load(_T("officer_vehicle.jpg"))))
		{
			HWND hwnd = ((CStatic*)GetDlgItem(IDC_STATIC_PIC))->GetSafeHwnd();	// 컨트롤 핸들 얻기
			HDC hdc = ::GetDC(hwnd);	// 컨트롤 DC 얻기
			carImg.StretchBlt(hdc, 0, 0, 640, 480, SRCCOPY);
		}
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR ClgofficerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void ClgofficerDlg::setMsg(CString msg)
{
	mtx.lock();
	this->m_msg += msg;
	this->m_msg += L"\r\n";
	mtx.unlock();
	this->ui_update();
}

void ClgofficerDlg::clearMsg()
{
	mtx.lock();
	this->m_msg.Empty();
	mtx.unlock();
}

void ClgofficerDlg::setStateText(CString state_text)
{
	mtx.lock();
	this->m_state = state_text;
	mtx.unlock();
}

void ClgofficerDlg::setAlertText(AlertT alertType, CString state_text)
{
	GetDlgItem(IDC_STATIC_ALERT)->SetWindowText(state_text);
}

void ClgofficerDlg::ui_update()
{
	this->PostMessage(UPDATE_MSG, 0, 0);
}

LRESULT ClgofficerDlg::OnReceivedMsgFromThread(WPARAM w, LPARAM l)
{
	this->UpdateData(FALSE);
	cEditMsg.LineScroll(cEditMsg.GetLineCount());

	return 0;
}

void ClgofficerDlg::OnBnClickedButtonLogin()
{
	lgc_state_e curSt = this->client->getCliStatus();
	if (curSt == LGC_ST_SVC_READY || curSt == LGC_ST_SVC_RUNNING)
	{
		this->client->setCliStatus(LGC_ST_DISCONNECT);
		return;
	}
	UpdateData(TRUE);
	CString strId, strPw, strOtp;
	GetDlgItemText(IDC_EDIT_ID, strId);
	GetDlgItemText(IDC_EDIT_PW, strPw);
	GetDlgItemText(IDC_EDIT_OTP, strOtp);
	UpdateData(FALSE);

#if 0	/* only for debugging, do not enable this code */
	setMsg(L"ID : " + strId);
	setMsg(L"PW : " + strPw);
	setMsg(L"OTP : " + strOtp);
#endif	/* only for debugging, do not enable this code */

	// TODO[Auth] input validatation
	if (strId.GetLength() > MAX_USR_ID_LENGTH || strId.GetLength() < MIN_USR_ID_LENGTH ||
		strPw.GetLength() > MAX_USR_PW_LENGTH || strPw.GetLength() < MIN_USR_PW_LENGTH ||
		strOtp.GetLength() != MAX_USR_OTP_LENGTH)
	{
		setMsg(L"invalid input");
		return;
	}
	
	// TODO[Auth] processing data ex) passwd hashing

	// TODO[Auth] Copy User credential to char*	// check pw
	//int length = cstr.GetLength();
	char uid[MAX_USR_ID_LENGTH + 1] = { 0, };
	char upw[MAX_USR_PW_LENGTH + 1] = { 0, };
	char uotp[MAX_USR_OTP_LENGTH + 1] = { 0, };

	memcpy(uid, CT2A(strId), strId.GetLength());
	memcpy(upw, CT2A(strPw), strPw.GetLength());
	memcpy(uotp, CT2A(strOtp), strOtp.GetLength());

	// after input validation and data is processed, set arguments and status to authenticating
	res_e res = this->client->setUserCredential(
		uid, (unsigned short)strnlen(uid, sizeof(uid)),
		upw, (unsigned short)strnlen(upw, sizeof(upw)),
		uotp, (unsigned short)strnlen(uotp, sizeof(uotp))
	);
	if (res != LGC_SUCCESS)
	{
		setMsg(L"invalid input");
		return;
	}
	
	this->client->setCliStatus(LGC_ST_AUTHENTICATING);	
}

void ClgofficerDlg::OnBnClickedButtonStart()
{
	if (this->client->getCliStatus() == LGC_ST_SVC_READY)
	{
		// get mode setting from ui setting
		struct demoMode_s dm;
		dm.vMode = getSelectedMedia();
		dm.vSaveMode = getSelectedSaveMode();
		dm.vRes = getSelectedRes();

		// set mode setting
		this->client->setDemoMode(dm);

		// set client status to svc running
		this->client->setCliStatus(LGC_ST_SVC_RUNNING);
	}
	else if (this->client->getCliStatus() == LGC_ST_SVC_RUNNING)
	{
		this->client->setCliStatus(LGC_ST_SVC_READY);
	}
}

void ClgofficerDlg::OnBnClickedButtonDisCon()
{
	this->client->setCliStatus(LGC_ST_DISCONNECT);
}

void ClgofficerDlg::DrawImage(cv::Mat mat)
{
	CImage image;
	if (0 != Mat2CImage(&mat, image))
	{
		setMsg(L"fail to convert mat to image");
	}

	//setMsg(L"success to convert mat to image");

	HWND hwnd = ((CStatic*)GetDlgItem(IDC_STATIC_PIC))->GetSafeHwnd();	// 컨트롤 핸들 얻기
	HDC hdc = ::GetDC(hwnd);	// 컨트롤 DC 얻기

	//image.BitBlt(hdc, 0, 0);
	image.StretchBlt(hdc, 0, 0, 640, 480, SRCCOPY);
}

int ClgofficerDlg::Mat2CImage(cv::Mat* mat, CImage& img) {
	if (!mat || mat->empty())
		return -1;
	int nBPP = mat->channels() * 8;
	img.Create(mat->cols, mat->rows, nBPP);
	if (nBPP == 8)
	{
		static RGBQUAD pRGB[256];
		for (int i = 0; i < 256; i++)
			pRGB[i].rgbBlue = pRGB[i].rgbGreen = pRGB[i].rgbRed = i;
		img.SetColorTable(0, 256, pRGB);
	}
	uchar* psrc = mat->data;
	uchar* pdst = (uchar*)img.GetBits();
	int imgPitch = img.GetPitch();
	for (int y = 0; y < mat->rows; y++)
	{
		memcpy(pdst, psrc, mat->cols * mat->channels());//mat->step is incorrect for those images created by roi (sub-images!)
		psrc += mat->step;
		pdst += imgPitch;
	}

	return 0;
}

BOOL ClgofficerDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 여기에 특수화된 코드를 추가 및/또는 기본 클래스를 호출합니다.
	if (pMsg->message == WM_KEYDOWN)
	{
		switch (pMsg->wParam)
		{
		case VK_RETURN:
			OnBnClickedButtonLogin();
		case VK_ESCAPE:
			return TRUE;
		default:
			break;
		}
	}

	return CDialogEx::PreTranslateMessage(pMsg);
}

void ClgofficerDlg::setUiEnable(lgc_state_e st)
{
	mtx.lock();
	switch (st)
	{
		case LGC_ST_CONNECTION_DONE:
			break;
		case LGC_ST_SVC_READY:
			GetDlgItem(IDC_EDIT_OTP)->SetWindowText(_T(""));
			//GetDlgItem(IDC_EDIT_ID)->SetWindowText(_T(""));
			GetDlgItem(IDC_EDIT_PW)->SetWindowText(_T(""));
			GetDlgItem(IDC_BUTTON_START)->EnableWindow(TRUE);
			GetDlgItem(IDC_BUTTON_START)->SetWindowText(L"Start");
			GetDlgItem(IDC_BUTTON_LOGIN)->SetWindowText(_T("Logout"));
			break;
		case LGC_ST_SVC_RUNNING:
			GetDlgItem(IDC_BUTTON_START)->SetWindowText(L"Stop");
			break;
		case LGC_ST_DISCONNECTED:
		case LGC_ST_DISCONNECT:
			GetDlgItem(IDC_BUTTON_LOGIN)->SetWindowText(_T("Login"));
			GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
			break;
		default:
			break;
	}
	mtx.unlock();
}

void ClgofficerDlg::OnClickedButtonEnc()
{
	std::vector<uint8_t> masterkey;
	Blob mBlob;
	std::vector<uint8_t>::iterator valueBytes;
	std::string str;
	int result = 0, rawLength = 0;

	std::fill(masterkey.begin(), masterkey.end(), 0);
	memset(&mBlob, 0, sizeof(Blob));

	result = loadMasterBlob(masterkey_path, &mBlob);
	if (result < 0)
	{
		setMsg(L"failed to load masterkey\n");
		return;
	}
	setMsg(L"success to load masterkey\n");

	rawLength = mBlob.length;
	masterkey.resize(rawLength);
	valueBytes = masterkey.begin();
	for (int i = 0; i < rawLength; i++) {
		valueBytes[i] = mBlob.value[i];
	}

	result = encryptAllData(AlertLogFile, &mBlob);
	if (result < 1) {
		setMsg(L"failed to decrypt plate info data\n");
		return ;
	}
	setMsg(L"success to decrypt plate info data\n");
	MessageBox(L"Success!", L"Encryption", MB_OK);
}


void ClgofficerDlg::OnClickedButtonDec()
{
	std::vector<uint8_t> masterkey;
	Blob mBlob;
	std::vector<uint8_t>::iterator valueBytes;
	std::string str;
	int result = 0, rawLength = 0;

	std::fill(masterkey.begin(), masterkey.end(), 0);
	memset(&mBlob, 0, sizeof(Blob));

	result = loadMasterBlob(masterkey_path, &mBlob);
	if (result < 0)
	{
		setMsg(L"failed to load masterkey\n");
		return;
	}
	setMsg(L"success to load masterkey mBlob\n");

	rawLength = mBlob.length;
	masterkey.resize(rawLength);
	valueBytes = masterkey.begin();
	for (int i = 0; i < rawLength; i++) {
		valueBytes[i] = mBlob.value[i];
	}

	result = decryptDatatoFile(EncAlertLogFile, masterkey, &mBlob);
	if (result < 1) {
		setMsg(L"failed to decrypt plate info data\n");
		return;
	}
	setMsg(L"success to decrypt plate info data\n");
	MessageBox(L"Success!", L"Decryption", MB_OK);
}


void ClgofficerDlg::OnClickedStaticFindPw()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	MessageBox(L"Contact IT Service\nCall) 1544 - 1544", L"Find Password", MB_OK);
}


HBRUSH ClgofficerDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);

	// TODO:  여기서 DC의 특성을 변경합니다.
	if (pWnd->GetDlgCtrlID() == IDC_STATIC_FIND_PW) {
		// 글자 색을 변경한다.
		pDC->SetTextColor(RGB(0, 0, 255));
	}

	// TODO:  기본값이 적당하지 않으면 다른 브러시를 반환합니다.
	return hbr;
}

void ClgofficerDlg::RadioMeida(UINT radio_num)
{
	UpdateData(TRUE);
	switch (radio_num)
	{
	case IDC_RADIO_MEIDA_LIVE:
		GetDlgItem(IDC_RADIO_RES_480P)->EnableWindow(TRUE);
		GetDlgItem(IDC_RADIO_RES_720P)->EnableWindow(TRUE);
		((CButton*)GetDlgItem(IDC_RADIO_RES_480P))->SetCheck(true);
		((CButton*)GetDlgItem(IDC_RADIO_RES_720P))->SetCheck(false);
		break;
	case IDC_RADIO_MEIDA_PLAYBACK:
	case IDC_RADIO_MEIDA_IMAGE:
	default:
		GetDlgItem(IDC_RADIO_RES_480P)->EnableWindow(FALSE);
		GetDlgItem(IDC_RADIO_RES_720P)->EnableWindow(FALSE);
		break;
	}
	UpdateData(FALSE);
}

Mode ClgofficerDlg::getSelectedMedia()
{
	Mode media = Mode::mPlayback_Video;
	UpdateData(TRUE);
	int nSelect = GetCheckedRadioButton(IDC_RADIO_MEIDA_LIVE, IDC_RADIO_MEIDA_IMAGE);
	UpdateData(FALSE);

	switch (nSelect)
	{
	case IDC_RADIO_MEIDA_LIVE:
		media = Mode::mLive_Video;
		break;
	case IDC_RADIO_MEIDA_PLAYBACK:
		media = Mode::mPlayback_Video;
		break;
	case IDC_RADIO_MEIDA_IMAGE:
		media = Mode::mImage_File;
		break;
	default:
		std::cout << "mPlayback_Video(default)" << std::endl;
		break;
	}

	return media;
}

VideoSaveMode ClgofficerDlg::getSelectedSaveMode()
{
	VideoSaveMode smode = VideoSaveMode::vSave;
	UpdateData(TRUE);
	int nSelect = GetCheckedRadioButton(IDC_RADIO_SAVE_N, IDC_RADIO_SAVE_Y_NO_ALPR);
	UpdateData(FALSE);

	switch (nSelect)
	{
	case IDC_RADIO_SAVE_N:
		smode = VideoSaveMode::vNoSave;
		break;
	case IDC_RADIO_SAVE_Y:
		smode = VideoSaveMode::vSave;
		break;
	case IDC_RADIO_SAVE_Y_NO_ALPR:
		smode = VideoSaveMode::vSaveWithNoALPR;
		break;
	default:
		std::cout << "vSave(default)" << std::endl;
		break;
	}

	return smode;
}

VideoResolution ClgofficerDlg::getSelectedRes()
{
	VideoResolution res = VideoResolution::rNone;
	UpdateData(TRUE);
	int nSelect = GetCheckedRadioButton(IDC_RADIO_RES_480P, IDC_RADIO_RES_720P);
	UpdateData(FALSE);

	switch (nSelect)
	{
	case IDC_RADIO_RES_480P:
		res = VideoResolution::r640X480;
		break;
	case IDC_RADIO_RES_720P:
		res = VideoResolution::r1280X720;
		break;
	default:
		std::cout << "rNone(default)" << std::endl;
		break;
	}

	return res;
}