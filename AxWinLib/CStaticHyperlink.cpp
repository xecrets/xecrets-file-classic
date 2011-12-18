#include "StdAfx.h"

#include "IStaticHyperlink.h"

namespace awl {
    class CStaticHyperlink : public IStaticHyperlink {
        friend IStaticHyperlink;

        static IStaticHyperlink *s_instance;
    public:
        static IStaticHyperlink& GetInstance();
        bool EnableHyperlink(HWND hWndControl);

    protected:
        CStaticHyperlink();

    private:
        CStaticHyperlink(const CStaticHyperlink& o) {}
        CStaticHyperlink& operator=(const CStaticHyperlink& o) {}

        static LRESULT CALLBACK ParentSubclassWndproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
        static LRESULT CALLBACK SubclassWndproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    };

    IStaticHyperlink *CStaticHyperlink::s_instance =  new CStaticHyperlink();

    CStaticHyperlink::CStaticHyperlink() {
    }

    IStaticHyperlink& IStaticHyperlink::GetInstance() {
        return *CStaticHyperlink::s_instance;
    }

    IStaticHyperlink::~IStaticHyperlink() {
    }

    LRESULT CALLBACK CStaticHyperlink::ParentSubclassWndproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
        WNDPROC pfnOriginalWndProc = reinterpret_cast<WNDPROC>(::GetProp(hwnd, L"awl::pfnOriginalWndProc"));

        switch (message) {
            // Set the right color of the text
            case WM_CTLCOLORSTATIC: {
                HDC hdc = (HDC)wParam;
                HWND hwndCtl = (HWND)lParam;

                // If the hyperlink flag is set, we'll change the color of this static control
                BOOL fHyperlink = GetProp(hwndCtl, L"awl::fHyperlink") != NULL;
                if (fHyperlink) {
                    LRESULT lr = CallWindowProc(pfnOriginalWndProc, hwnd, message, wParam, lParam);
                    SetTextColor(hdc, RGB(0, 0, 192));
                    return lr;
                }

                break;
            }
            case WM_DESTROY: {
                SetWindowLongPtr(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(pfnOriginalWndProc));
                break;
            }
        }
        return CallWindowProc(pfnOriginalWndProc, hwnd, message, wParam, lParam);
    }

    LRESULT CALLBACK CStaticHyperlink::SubclassWndproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
        WNDPROC pfnOriginalWndProc = reinterpret_cast<WNDPROC>(::GetProp(hwnd, L"awl::pfnOriginalWndProc"));

        switch (message) {
            case WM_DESTROY: {
                SetWindowLongPtr(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(pfnOriginalWndProc));

                HFONT hOriginalFont = (HFONT)GetProp(hwnd, L"awl::hOriginalFont");
                SendMessage(hwnd, WM_SETFONT, (WPARAM)hOriginalFont, 0);
                RemoveProp(hwnd, L"awl::hOriginalFont");

                HFONT hHyperlinkFont = (HFONT)GetProp(hwnd, L"awl::hHyperlinkFont");
                DeleteObject(hHyperlinkFont);
                RemoveProp(hwnd, L"awl::hHyperlinkFont");

                RemoveProp(hwnd, L"awl::fHyperlink");
                break;
            }
            case WM_MOUSEMOVE: {
                // Check if we have captured the mouse
                if (GetCapture() != hwnd) {
                    // Yes, change the font and capture it
                    HFONT hHyperlinkFont = (HFONT)GetProp(hwnd, L"awl::hHyperlinkFont");
                    SendMessage(hwnd, WM_SETFONT, (WPARAM)hHyperlinkFont, FALSE);
                    InvalidateRect(hwnd, NULL, FALSE);
                    SetCapture(hwnd);
                } else {
                    RECT rect;
                    GetWindowRect(hwnd, &rect);

                    POINT pt = { LOWORD(lParam), HIWORD(lParam) };
                    ClientToScreen(hwnd, &pt);

                    // If we have captured, but no longer are inside, restore the orginal font and release the capture
                    if (!PtInRect(&rect, pt)) {
                        HFONT hHyperlinkFont = (HFONT)GetProp(hwnd, L"awl::hOriginalFont");
                        SendMessage(hwnd, WM_SETFONT, (WPARAM)hHyperlinkFont, FALSE);
                        InvalidateRect(hwnd, NULL, FALSE);
                        ReleaseCapture();
                    }
                }
                break;
            }
            case WM_SETCURSOR: {
                // Use IDC_HAND if available, otherwise IDC_ARROW
                HCURSOR hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_HAND));
                if (hCursor == NULL) {
                    hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_ARROW));
                }
                SetCursor(hCursor);
                return TRUE;
            }
        }
        return CallWindowProc(pfnOriginalWndProc, hwnd, message, wParam, lParam);
    }

    bool CStaticHyperlink::EnableHyperlink(HWND hWndControl) {
        // Subclass the parent so we can color the controls as we desire.
        HWND hwndParent = GetParent(hWndControl);
        if (hwndParent != NULL) {
            WNDPROC pfnOriginalWndProc = reinterpret_cast<WNDPROC>(GetWindowLongPtr(hwndParent, GWLP_WNDPROC));
            // Check if we already have subclassed
            if (pfnOriginalWndProc != &CStaticHyperlink::ParentSubclassWndproc) {
                ::SetProp(hwndParent, L"awl::pfnOriginalWndProc", reinterpret_cast<HANDLE>(pfnOriginalWndProc));
                SetWindowLongPtr(hwndParent, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&CStaticHyperlink::ParentSubclassWndproc));
            }
        }

        // Static controls won't by default send notifications. You may also need to check that it has been given a valid ID, not -1
        DWORD dwStyle = GetWindowLong(hWndControl, GWL_STYLE);
        SetWindowLongPtr(hWndControl, GWL_STYLE, dwStyle | SS_NOTIFY);

        // Subclass the existing control.
        WNDPROC pfnOriginalWndProc = reinterpret_cast<WNDPROC>(GetWindowLongPtr(hWndControl, GWLP_WNDPROC));
        ::SetProp(hWndControl, L"awl::pfnOriginalWndProc", reinterpret_cast<HANDLE>(pfnOriginalWndProc));
        SetWindowLongPtr(hWndControl, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&CStaticHyperlink::SubclassWndproc));

        // Create a font that we use when the mouse hovers over the control, and save the original font
        HFONT hOriginalFont = (HFONT)SendMessage(hWndControl, WM_GETFONT, 0, 0);
        SetProp(hWndControl, L"awl::hOriginalFont", (HANDLE)hOriginalFont);

        LOGFONT lf;
        GetObject(hOriginalFont, sizeof lf, &lf);
        lf.lfUnderline = TRUE;

        HFONT hHyperlinkFont = CreateFontIndirect(&lf);
        SetProp(hWndControl, L"awl::hHyperlinkFont", (HANDLE)hHyperlinkFont);

        // Set a flag on the control so we know what color it should be.
        SetProp(hWndControl, L"awl::fHyperlink", (HANDLE)1);

        return true;
    }
}