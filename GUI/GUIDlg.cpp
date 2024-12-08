// GUIDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "GUI.h"
#include "GUIDlg.h"
#include "afxdialogex.h"
#include "../Driver/LayerHandles.h"

#pragma warning(disable:4996)  // Unsafe sprintf

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


constexpr const CHAR* DEVICE_NAME = "\\\\.\\IDPS Sniffer Device";
// Global Handle for now
HANDLE deviceHandle = NULL;

// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	// Implementation
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


// CGUIDlg dialog



CGUIDlg::CGUIDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_GUI_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CGUIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CGUIDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON2, &CGUIDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON1, &CGUIDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON3, &CGUIDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CGUIDlg message handlers

BOOL CGUIDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
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

	// Set the icon for this dialog. The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CGUIDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon. For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CGUIDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor
// to display while the user drags the minimized window.
HCURSOR CGUIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CGUIDlg::OnBnClickedButton2()
{
	// Try to open sniffer device, notify status to user
	CloseHandle(deviceHandle); // No need to validate handle before closing
}


void CGUIDlg::OnBnClickedButton1()
{
	// Try to open sniffer device, notify status to user

	deviceHandle = CreateFileW(L"\\\\.\\SnifferDeviceLink", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);

	if (deviceHandle == INVALID_HANDLE_VALUE)
	{
		char buffer[24];
		sprintf(buffer, "Error code: %lu", GetLastError());
		MessageBoxA(NULL, buffer, "Error", MB_ICONERROR);
		MessageBeep(MB_ICONERROR);
		return;
	}

	MessageBoxW(L"Found sniffer device successfully", L"Yay!", MB_ICONASTERISK);
}


void CGUIDlg::OnBnClickedButton3()
{
	DWORD bytesReturned;
	IOCTL_HANDLES ioctl;

	ioctl.pid = GetCurrentProcessId();
	ioctl.mutexes.ethernet = CreateMutexW(NULL, FALSE, ETHERNET_MUTEX_PATH);
	ioctl.mutexes.internet = CreateMutexW(NULL, FALSE, INTERNET_MUTEX_PATH);
	ioctl.mutexes.transport = CreateMutexW(NULL, FALSE, TRANSPORT_MUTEX_PATH);
	ioctl.mutexes.application = CreateMutexW(NULL, FALSE, APPLICATION_MUTEX_PATH);

	if (ioctl.mutexes.ethernet == INVALID_HANDLE_VALUE || ioctl.mutexes.internet == INVALID_HANDLE_VALUE || ioctl.mutexes.transport == INVALID_HANDLE_VALUE || ioctl.mutexes.application == INVALID_HANDLE_VALUE)
	{
		MessageBoxW(L"Failed to create or open mutex.", L":(", MB_ICONASTERISK);
		return;
	}


	BOOL success = DeviceIoControl(
		deviceHandle,           // Handle to the device
		IOCTL_SEND_HANDLES,     // IOCTL code
		&ioctl,                 // Input buffer (pointer to the struct)
		sizeof(IOCTL_HANDLES),  // Size of input buffer
		NULL,                   // Output buffer (not needed here)
		0,                      // Size of output buffer
		&bytesReturned,         // Bytes returned
		NULL                    // Overlapped (optional, NULL for synchronous I/O)
	);

	if (!success)
		MessageBoxW(L"DeviceIoControl failed.", L":(", MB_ICONASTERISK);
	else
		MessageBoxW(L"Struct sent successfully.", L":)", MB_ICONASTERISK);
}
