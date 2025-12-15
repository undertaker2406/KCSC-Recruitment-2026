
<img width="400" height="500" alt="image" src="https://github.com/user-attachments/assets/8df8d905-840d-418f-919b-9fa7c29f650d" />

# Mở chương trình để test chức năng

<img width="637" height="376" alt="image" src="https://github.com/user-attachments/assets/1c11c889-9e7f-43da-9de3-64819d246d70" />

Chương bắt mình nhập vào user và serial key để đăng nhập

Mình thử cố tình nhập sai thì nó hiện lên một cái message box thông báo Activation Failed!

<img width="817" height="486" alt="image" src="https://github.com/user-attachments/assets/85010294-85ad-469b-9f53-436b8165e090" />

Còn nếu không nhập gì nó hiện ra message box yêu cầu mình nhập đủ trường thông tin

<img width="621" height="353" alt="image" src="https://github.com/user-attachments/assets/ad36724c-8911-43bf-aa5a-83c8721f81db" />

Mình có thử vứt program vào ghidra để patch nhảy đến chỗ thành công luôn thì hiện ra Activation Success! nhưng không hiện flag. Các anh giấu kĩ quá :P

<img width="801" height="435" alt="image" src="https://github.com/user-attachments/assets/eb9fb5b8-0707-4b27-a85e-93d8f799f3ae" />

Từ các lần test trên mình đã rút ra vài được hoạt động chính của chương trình:

- Nhập tên người dùng và serial key, nếu sai thì hiện ra một cửa số Activation Failed! Còn nếu đúng thì hiện ra Cửa số Activation Success! kèm flag.
- Không thể patch được => chương trình đã sử dụng user và serial key để có thể giải mã flag.
- Đây là một bài keygen với serial key được xào nấu từ user name đúng.

# Static Analysis

Mình ném chương trình vào ghidra để đọc mã giả. Để tìm hàm logic chính của chương trình, mình tìm kiếm chuỗi tiêu đề của phần mềm khi mở ra là ***"KCSC Software Activation"***. Ta thấy chuỗi được gọi bởi 2 hàm ***FUN_140002c82*** ở dòng 140002e5f và ***LAB_1400022f2*** ở dòng 1400024a1

<img width="1592" height="835" alt="image" src="https://github.com/user-attachments/assets/a24a0760-7943-4ab5-b454-6a6feb224a28" />

Lần theo các lời gọi hàm trong ghidra thì mình thấy được từ entry sẽ dần dần đi vào hàm ***FUN_140002c82*** rồi sau đó hàm ***FUN_140002c82*** sẽ gọi đến ***LAB_1400022f2***  thông qua 2 dòng là

```c
local_a8 = ZEXT816(0x1400022f2) << 0x40;
...
AVar2 = RegisterClassW((WNDCLASSW *)local_a8);
```

Sau khi đọc quả ***LAB_1400022f2*** ta có thể biết được đoạn code này sẽ khởi tạo các cửa sổ, vùng text gõ văn bản để nhập user và serial key, và có cả đoạn code sẽ kiểm tra vùng nhập user và serial key để check Activation. Vậy ta có thể đoán được hàm ***FUN_140002c82*** sẽ chạy trước và gọi đến ***LAB_1400022f2*** để khởi tạo các cửa sổ, các nút bấm và vùng gõ user ,serial key của chương trình. Chúng ta sẽ tìm hiểu hàm ***FUN_140002c82*** trước.

```c


undefined4 FUN_140002c82(HINSTANCE param_1,undefined8 param_2,undefined8 param_3,int param_4)

{
  undefined1 auVar1 [16];
  ATOM AVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  BOOL BVar6;
  undefined8 *puVar7;
  longlong lVar8;
  HCURSOR pHVar9;
  HWND hWnd;
  ulonglong uVar10;
  undefined8 *puVar11;
  tagMSG local_e8;
  tagRECT local_b8;
  undefined1 local_a8 [16];
  undefined1 local_98 [16];
  undefined1 local_88 [16];
  undefined1 local_78 [16];
  WCHAR *local_68;
  WCHAR local_58 [20];
  INITCOMMONCONTROLSEX local_30;
  
  local_30.dwSize = 8;
  local_30.dwICC = 0x4000;
  InitCommonControlsEx(&local_30);
  puVar7 = (undefined8 *)VirtualAlloc((LPVOID)0x0,0x110,0x3000,0x40);
  DAT_140020f38 = puVar7;
  if (puVar7 == (undefined8 *)0x0) {
    MessageBoxW((HWND)0x0,L"Failed to initialize!",L"Error",0x10);
    uVar3 = 0;
  }
  else {
    *puVar7 = DAT_140016600;
    puVar7[0x21] = DAT_140016708;
    lVar8 = (longlong)puVar7 - (longlong)((ulonglong)(puVar7 + 1) & 0xfffffffffffffff8);
    puVar11 = (undefined8 *)((longlong)&DAT_140016600 - lVar8);
    puVar7 = (undefined8 *)((ulonglong)(puVar7 + 1) & 0xfffffffffffffff8);
    for (uVar10 = (ulonglong)((int)lVar8 + 0x110U >> 3); uVar10 != 0; uVar10 = uVar10 - 1) {
      *puVar7 = *puVar11;
      puVar11 = puVar11 + 1;
      puVar7 = puVar7 + 1;
    }
    builtin_memcpy(local_58,L"KCSCKeyGenClass",0x20);
    local_88 = (undefined1  [16])0x0;
    local_78 = (undefined1  [16])0x0;
    local_a8 = ZEXT816(0x1400022f2) << 0x40;
    local_98._8_8_ = 0;
    local_98._0_8_ = param_1;
    local_98 = local_98 << 0x40;
    local_68 = local_58;
    pHVar9 = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
    auVar1._8_8_ = 0;
    auVar1._0_8_ = local_78._8_8_;
    local_78 = auVar1 << 0x40;
    local_88._8_8_ = pHVar9;
    local_88._0_8_ = LoadIconW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
    AVar2 = RegisterClassW((WNDCLASSW *)local_a8);
    uVar3 = 0;
    if (AVar2 != 0) {
      hWnd = CreateWindowExW(1,local_58,L"KCSC Software Activation",0xca0000,-0x80000000,-0x80000 000
                             ,0x208,0x136,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
      uVar3 = 0;
      if (hWnd != (HWND)0x0) {
        ShowWindow(hWnd,param_4);
        UpdateWindow(hWnd);
        GetWindowRect(hWnd,&local_b8);
        iVar4 = GetSystemMetrics(0);
        iVar5 = GetSystemMetrics(1);
        SetWindowPos(hWnd,(HWND)0x0,(iVar4 - (local_b8.right - local_b8.left)) / 2,
                     (iVar5 - (local_b8.bottom - local_b8.top)) / 2,0,0,5);
        while (BVar6 = GetMessageW(&local_e8,(HWND)0x0,0,0), uVar3 = (undefined4)local_e8.wParam,
              0 < BVar6) {
          TranslateMessage(&local_e8);
          DispatchMessageW(&local_e8);
        }
      }
    }
  }
  return uVar3;
}


```

Chú ý đến đoạn

```c
  puVar7 = (undefined8 *)VirtualAlloc((LPVOID)0x0,0x110,0x3000,0x40);
  DAT_140020f38 = puVar7;
  if (puVar7 == (undefined8 *)0x0) {
    MessageBoxW((HWND)0x0,L"Failed to initialize!",L"Error",0x10);
    uVar3 = 0;
  }
  else {
    *puVar7 = DAT_140016600;
```

Khá là đáng ngờ vì hàm xin cấp phát một vùng nhớ có quyền thực thi (VirtualAlloc(..., 0x40): Tham số 0x40 là PAGE_EXECUTE_READWRITE. Nó xin cấp phát một vùng nhớ cho phép Đọc + Ghi + Thực thi). ***DAT_140020f38*** chứa địa chỉ của vùng nhớ đó, sau đó lưu data ***DAT_140016600*** vào vùng nhớ này. Mình đoán chuỗi bytes của vùng DAT_140016600 khả năng cao chứa những bytes tương đương với lệnh opcode của asm. Nên mình vào đó thử disassemble vùng ***DAT_140016600*** thì được đoạn psuedo code.

```c

undefined8 UndefinedFunction_140016608(char *param_1,longlong param_2,longlong param_3)

{
  int in_EAX;
  longlong lVar1;
  longlong lVar2;
  uint uVar3;
  ulonglong uVar4;
  int iVar5;
  
  if (((char)in_EAX == '\0' && in_EAX != 0) && (lVar1 = 0, param_1 != (char *)0x0)) {
    do {
      if (param_1[lVar1] == '\0') break;
      lVar1 = lVar1 + 1;
    } while (lVar1 != 0x100);
    lVar2 = 0;
    do {
      if (*(char *)(param_2 + lVar2) == '\0') {
        iVar5 = (int)lVar2;
        goto LAB_140016656;
      }
      lVar2 = lVar2 + 1;
    } while (lVar2 != 0x100);
    iVar5 = 0x100;
LAB_140016656:
    if ((iVar5 != 0) && ((int)lVar1 == 0xc)) {
      if (*param_1 != 'k') {
        return 0;
      }
      if (param_1[2] != 'a') {
        return 0;
      }
      if (param_1[4] != '3') {
        return 0;
      }
      if (param_1[6] != '3') {
        return 0;
      }
      if (param_1[8] != '5') {
        return 0;
      }
      if (param_1[10] != 'n') {
        return 0;
      }
      if (param_1[1] != 'm') {
        return 0;
      }
      if (param_1[3] != 'r') {
        return 0;
      }
      if (param_1[5] != 'v') {
        return 0;
      }
      if (param_1[7] != 'r') {
        return 0;
      }
      if (param_1[9] != '!') {
        return 0;
      }
      if (param_1[0xb] != '9') {
        return 0;
      }
      uVar4 = 0;
      uVar3 = 0x1337;
      while (uVar3 = (uint)(byte)param_1[(ulonglong)uVar3 % 0xc] +
                     ((uint)(byte)param_1[(int)((longlong)
                                                ((ulonglong)(uint)((int)uVar4 >> 0x1f) << 0x20 |
                                                uVar4 & 0xffffffff) % 0xc)] ^
                     (int)*(char *)(param_2 + uVar4) ^ uVar3),
            *(uint *)(param_3 + uVar4 * 4) == uVar3) {
        uVar4 = uVar4 + 1;
        if (iVar5 <= (int)uVar4) {
          return 1;
        }
      }
    }
  }
  return 0;
}
```

Có vẻ đây là một hàm gen key theo như ta phỏng đoán theo tên của chương trình và lúc test chương trình. Ta biết được địa chỉ của đoạn code này đang được 
***DAT_140020f38*** nắm giữ. Tạm thời mình chỉ cần nhớ thế đã, chúng ta sẽ tìm hiểu các dòng dưới của chương trình.

Ở dòng dưới có các hàm khởi tạo windown, loadicon, show window và update window...vv Nhưng mình chú ý đến đoạn

```c
local_a8 = ZEXT816(0x1400022f2) << 0x40;
...
AVar2 = RegisterClassW((WNDCLASSW *)local_a8);
```

đối chiếu dòng cuối qua mã assembly

```asm
       140002db7 ff  15  2b       CALL       qword ptr [->USER32.DLL::LoadCursorW ]           = 00023456
                 fd  01  00

```
Có vẻ nó đã gọi đến hàm ở địa chỉ ***0x1400022f2*** nên giờ chúng ta sẽ bắt đầu đi vào hàm này để xem nó diễn ra cái gì. Click đúp vô địa chỉ ta được đoạn psuedo code:

```c

HBRUSH UndefinedFunction_1400022f2(HWND param_1,uint param_2,HDC param_3,longlong param_4)

{
  undefined8 uVar1;
  HDC hDC;
  int iVar2;
  HINSTANCE hInstance;
  HWND pHVar3;
  HFONT wParam;
  HPEN h;
  HGDIOBJ pvVar4;
  HGDIOBJ h_00;
  undefined1 *puVar5;
  size_t sVar6;
  HBRUSH pHVar7;
  longlong lVar8;
  undefined8 *puVar9;
  tagRECT *ptVar10;
  COLORREF color;
  char acStack_448 [256];
  RECT aRStack_348 [16];
  tagRECT atStack_248 [17];
  undefined1 uStack_130;
  
  if (param_2 == 0x2b) {
    if (*(int *)(param_4 + 4) != 3) {
      return (HBRUSH)0x0;
    }
    hDC = *(HDC *)(param_4 + 0x20);
    aRStack_348[0]._0_8_ = *(undefined8 *)(param_4 + 0x28);
    aRStack_348[0]._8_8_ = *(undefined8 *)(param_4 + 0x30);
    pHVar7 = DAT_140020f18;
    if (DAT_140020f08 != 0) {
      pHVar7 = DAT_140020f10;
    }
    FillRect(hDC,aRStack_348,pHVar7);
    color = 0xb98029;
    if (DAT_140020f08 != 0) {
      color = 0xdb9834;
    }
    h = CreatePen(0,1,color);
    pvVar4 = SelectObject(hDC,h);
    h_00 = GetStockObject(5);
    SelectObject(hDC,h_00);
    RoundRect(hDC,aRStack_348[0].left,aRStack_348[0].top,aRStack_348[0].right,aRStack_348[0].botto m,
              5,5);
    SelectObject(hDC,pvVar4);
    DeleteObject(h);
    GetWindowTextW(*(HWND *)(param_4 + 0x18),(LPWSTR)atStack_248,0x100);
    SetBkMode(hDC,1);
    SetTextColor(hDC,0xffffff);
    pvVar4 = SelectObject(hDC,DAT_140020f30);
    DrawTextW(hDC,(LPCWSTR)atStack_248,-1,aRStack_348,0x25);
    SelectObject(hDC,pvVar4);
    return (HBRUSH)0x1;
  }
  if (param_2 < 0x2c) {
    if (param_2 == 2) {
      if (DAT_140020f38 != (code *)0x0) {
        VirtualFree(DAT_140020f38,0,0x8000);
      }
      if (DAT_140020f30 != (HFONT)0x0) {
        DeleteObject(DAT_140020f30);
      }
      if (DAT_140020f28 != (HFONT)0x0) {
        DeleteObject(DAT_140020f28);
      }
      if (DAT_140020f20 != (HBRUSH)0x0) {
        DeleteObject(DAT_140020f20);
      }
      if (DAT_140020f18 != (HBRUSH)0x0) {
        DeleteObject(DAT_140020f18);
      }
      if (DAT_140020f10 != (HBRUSH)0x0) {
        DeleteObject(DAT_140020f10);
      }
      PostQuitMessage(0);
      return (HBRUSH)0x0;
    }
    if (param_2 == 0x14) {
      GetClientRect(param_1,atStack_248);
      FillRect(param_3,atStack_248,DAT_140020f20);
      return (HBRUSH)0x1;
    }
    if (param_2 == 1) {
      hInstance = (HINSTANCE)GetWindowLongPtrW(param_1,-6);
      DAT_140020f30 = CreateFontW(0x14,0,0,0,400,0,0,0,1,0,0,5,0,L"Segoe UI");
      DAT_140020f28 = CreateFontW(0x16,0,0,0,700,0,0,0,1,0,0,5,0,L"Segoe UI");
      DAT_140020f20 = CreateSolidBrush(0xf5f0f0);
      DAT_140020f18 = CreateSolidBrush(0xb98029);
      DAT_140020f10 = CreateSolidBrush(0xdb9834);
      pHVar3 = CreateWindowExW(0,L"STATIC",L"KCSC Software Activation",0x50000001,0,0xf,500,0x1e,
                               param_1,(HMENU)0x0,hInstance,(LPVOID)0x0);
      SendMessageW(pHVar3,0x30,(WPARAM)DAT_140020f28,1);
      CreateWindowExW(0,L"STATIC",L"",0x50000010,0x14,0x37,0x1cc,2,param_1,(HMENU)0x0,hInstance,
                      (LPVOID)0x0);
      pHVar3 = CreateWindowExW(0,L"STATIC",L"Username:",0x50000000,0x1e,0x50,100,0x14,param_1,
                               (HMENU)0x0,hInstance,(LPVOID)0x0);
      SendMessageW(pHVar3,0x30,(WPARAM)DAT_140020f30,1);
      DAT_140020f50 =
           CreateWindowExW(0x200,L"EDIT",L"",0x50000080,0x8c,0x4b,0x140,0x1e,param_1,(HMENU)0x1,
                           hInstance,(LPVOID)0x0);
      SendMessageW(DAT_140020f50,0x30,(WPARAM)DAT_140020f30,1);
      pHVar3 = CreateWindowExW(0,L"STATIC",L"Serial Key:",0x50000000,0x1e,0x7d,100,0x14,param_1,
                               (HMENU)0x0,hInstance,(LPVOID)0x0);
      SendMessageW(pHVar3,0x30,(WPARAM)DAT_140020f30,1);
      DAT_140020f48 =
           CreateWindowExW(0x200,L"EDIT",L"",0x50000080,0x8c,0x78,0x140,0x1e,param_1,(HMENU)0x2,
                           hInstance,(LPVOID)0x0);
      SendMessageW(DAT_140020f48,0x30,(WPARAM)DAT_140020f30,1);
      DAT_140020f40 =
           CreateWindowExW(0,L"BUTTON",L"Activate License",0x5000000b,0xaf,0xaa,0x96,0x28,param_1 ,
                           (HMENU)0x3,hInstance,(LPVOID)0x0);
      SendMessageW(DAT_140020f40,0x30,(WPARAM)DAT_140020f30,1);
      SetWindowSubclass(DAT_140020f40,(SUBCLASSPROC)&LAB_140001700,0,0);
      pHVar3 = CreateWindowExW(0,L"STATIC",L"Enter your username and serial key to activate",
                               0x50000001,0,0xe6,500,0x14,param_1,(HMENU)0x0,hInstance,(LPVOID)0x0 );
      wParam = CreateFontW(0x10,0,0,0,400,0,0,0,1,0,0,5,0,L"Segoe UI");
      SendMessageW(pHVar3,0x30,(WPARAM)wParam,1);
      return (HBRUSH)0x0;
    }
  }
  else {
    if (param_2 == 0x133) {
      SetTextColor(param_3,0x503e2c);
      SetBkColor(param_3,0xffffff);
      pHVar7 = (HBRUSH)GetStockObject(0);
      return pHVar7;
    }
    if (param_2 == 0x138) {
      SetTextColor(param_3,0x503e2c);
      SetBkColor(param_3,0xf5f0f0);
      return DAT_140020f20;
    }
    if (param_2 == 0x111) {
      if ((short)param_3 != 3) {
        return (HBRUSH)0x0;
      }
      if (((ulonglong)param_3 & 0xffff0000) == 0) {
        GetWindowTextA(DAT_140020f50,acStack_448,0x100);
        GetWindowTextA(DAT_140020f48,(LPSTR)aRStack_348,0x100);
        if ((acStack_448[0] != '\0') && ((char)aRStack_348[0].left != '\0')) {
          if ((DAT_140020f38 == (code *)0x0) ||
             (iVar2 = (*DAT_140020f38)(acStack_448,aRStack_348,&DAT_140016520), iVar2 != 1)) {
            puVar5 = FUN_140002242(0x1400161a0,(uint *)&DAT_140016140);
            FUN_1400153b0(&DAT_14001f4a0,0x400,&DAT_14001734e,puVar5);
            FUN_1400017a6(param_1,(wchar_t *)&DAT_14001f4a0,0);
          }
          else {
            puVar9 = &DAT_140016020;
            ptVar10 = atStack_248;
            for (lVar8 = 0x23; lVar8 != 0; lVar8 = lVar8 + -1) {
              uVar1 = *puVar9;
              ptVar10->left = (int)uVar1;
              ptVar10->top = (int)((ulonglong)uVar1 >> 0x20);
              puVar9 = puVar9 + 1;
              ptVar10 = (tagRECT *)&ptVar10->right;
            }
            sVar6 = strlen((char *)aRStack_348);
            FUN_1400021bd((longlong)aRStack_348,(int)sVar6,(byte *)atStack_248,0x118);
            uStack_130 = 0;
            FUN_1400153b0(&DAT_14001f4a0,0x400,&DAT_14001734e,atStack_248);
            FUN_1400017a6(param_1,(wchar_t *)&DAT_14001f4a0,1);
          }
          return (HBRUSH)0x0;
        }
        MessageBoxW(param_1,L"Please enter both Username and Serial Key!",L"Input Required",0x30) ;
        return (HBRUSH)0x0;
      }
      return (HBRUSH)0x0;
    }
  }
  pHVar7 = (HBRUSH)DefWindowProcW(param_1,param_2,(WPARAM)param_3,param_4);
  return pHVar7;
}


```

Code khá dài nhưng chúng ta sẽ chỉ cần chú ý vào đoạn bắt đầu hàm ***GetWindowTextA()*** . Có vẻ đây là đoạn nó lấy dữ liệu từ phần text field của user và serial key. Lưu user nhập được từ vùng ***DAT_140020f50*** vào acStack_448, lưu serial key nhập được từ vùng ***DAT_140020f48*** vào aRStack_348. Và kiểm tra các hàm diều kiện

```c
               GetWindowTextA(DAT_140020f50,acStack_448,0x100);
        GetWindowTextA(DAT_140020f48,(LPSTR)aRStack_348,0x100);
        if ((acStack_448[0] != '\0') && ((char)aRStack_348[0].left != '\0')) {
          if ((DAT_140020f38 == (code *)0x0) ||
             (iVar2 = (*DAT_140020f38)(acStack_448,aRStack_348,&DAT_140016520), iVar2 != 1)) {
            puVar5 = FUN_140002242(0x1400161a0,(uint *)&DAT_140016140);
            FUN_1400153b0(&DAT_14001f4a0,0x400,&DAT_14001734e,puVar5);
            FUN_1400017a6(param_1,(wchar_t *)&DAT_14001f4a0,0);
          }
          else {
            puVar9 = &DAT_140016020;
            ptVar10 = atStack_248;
            for (lVar8 = 0x23; lVar8 != 0; lVar8 = lVar8 + -1) {
              uVar1 = *puVar9;
              ptVar10->left = (int)uVar1;
              ptVar10->top = (int)((ulonglong)uVar1 >> 0x20);
              puVar9 = puVar9 + 1;
              ptVar10 = (tagRECT *)&ptVar10->right;
            }
            sVar6 = strlen((char *)aRStack_348);
            FUN_1400021bd((longlong)aRStack_348,(int)sVar6,(byte *)atStack_248,0x118);
            uStack_130 = 0;
            FUN_1400153b0(&DAT_14001f4a0,0x400,&DAT_14001734e,atStack_248);
            FUN_1400017a6(param_1,(wchar_t *)&DAT_14001f4a0,1);
          }
          return (HBRUSH)0x0;
        }
        MessageBoxW(param_1,L"Please enter both Username and Serial Key!",L"Input Required",0x30) ;
```

Nó kiểm tra xem ```c (acStack_448[0] != '\0') && ((char)aRStack_348[0].left != '\0') ``` để kiểm tra các trường dữ liệu có nhập đủ không. Nếu không đủ sẽ pop up ra thông báo  ```c MessageBoxW(param_1,L"Please enter both Username and Serial Key!",L"Input Required",0x30); ``` . Còn nếu đủ kiểm tra tiếp điều kiện ***DAT_140020f38*** == (code*)0x0 đây là vùng nhớ mà mình bảo ban nãy chứa địa chỉ của vùng thực thi được cấp phát, xem cấp phát và lưu dữ liệu thành công hay không.

```c
          if ((DAT_140020f38 == (code *)0x0) ||
             (iVar2 = (*DAT_140020f38)(acStack_448,aRStack_348,&DAT_140016520), iVar2 != 1)) {
            puVar5 = FUN_140002242(0x1400161a0,(uint *)&DAT_140016140);
            FUN_1400153b0(&DAT_14001f4a0,0x400,&DAT_14001734e,puVar5);
            FUN_1400017a6(param_1,(wchar_t *)&DAT_14001f4a0,0);
          }
```

Nếu điều kiện thỏa mãn thì sẽ thực thi khối bên trong. Mình cũng không biết rõ ***FUN_1400153b0*** sẽ làm gì, nhưng mà hàm ***FUN_1400017a6** khá là thú vị, vì đây là hàm sẽ hiện ra thông báo Success và Fail của chương trình.

```c

void FUN_1400017a6(HWND param_1,wchar_t *param_2,int param_3)

{
  undefined1 auVar1 [16];
  int iVar2;
  int iVar3;
  BOOL BVar4;
  HINSTANCE pHVar5;
  HCURSOR pHVar6;
  wchar_t *lpCaption;
  UINT uType;
  tagMSG local_d8;
  tagRECT local_a8;
  undefined1 local_98 [16];
  undefined1 local_88 [16];
  undefined1 local_78 [16];
  undefined1 local_68 [16];
  LPCWSTR local_58;
  WCHAR local_48 [16];
  
  DAT_140020ee0 = param_3;
  wcscpy_s((wchar_t *)&DAT_14001fee0,0x800,param_2);
  builtin_memcpy(local_48,L"KCSCFlagDialog",0x1e);
  local_88 = (undefined1  [16])0x0;
  local_78 = (undefined1  [16])0x0;
  local_68 = (undefined1  [16])0x0;
  local_58 = (LPCWSTR)0x0;
  local_98 = ZEXT816(0x140001b4e) << 0x40;
  pHVar5 = (HINSTANCE)GetWindowLongPtrW(param_1,-6);
  local_58 = local_48;
  local_88._8_8_ = pHVar5;
  pHVar6 = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  auVar1._8_8_ = 0;
  auVar1._0_8_ = local_68._8_8_;
  local_68 = auVar1 << 0x40;
  local_78._8_8_ = pHVar6;
  if (param_3 == 0) {
    local_78._0_8_ = LoadIconW((HINSTANCE)0x0,(LPCWSTR)0x7f01);
    RegisterClassW((WNDCLASSW *)local_98);
    DAT_140020f00 =
         CreateWindowExW(9,local_48,L"Activation Failed",0x90c80000,0,0,0x28a,0x168,param_1,
                         (HMENU)0x0,(HINSTANCE)local_88._8_8_,(LPVOID)0x0);
    if (DAT_140020f00 == (HWND)0x0) {
      lpCaption = L"Activation Failed";
      uType = 0x10;
LAB_140001a4c:
      DAT_140020f00 = (HWND)0x0;
      MessageBoxW(param_1,param_2,lpCaption,uType);
      return;
    }
  }
  else {
    local_78._0_8_ = LoadIconW((HINSTANCE)0x0,(LPCWSTR)0x7f04);
    RegisterClassW((WNDCLASSW *)local_98);
    DAT_140020f00 =
         CreateWindowExW(9,local_48,L"Activation Successful",0x90c80000,0,0,0x28a,0x168,param_1,
                         (HMENU)0x0,(HINSTANCE)local_88._8_8_,(LPVOID)0x0);
    if (DAT_140020f00 == (HWND)0x0) {
      lpCaption = L"Activation Successful";
      uType = 0x40;
      goto LAB_140001a4c;
    }
  }
  GetWindowRect(DAT_140020f00,&local_a8);
  iVar2 = GetSystemMetrics(0);
  iVar3 = GetSystemMetrics(1);
  SetWindowPos(DAT_140020f00,(HWND)0xffffffffffffffff,(iVar2 - (local_a8.right - local_a8.left)) / 2
               ,(iVar3 - (local_a8.bottom - local_a8.top)) / 2,0,0,1);
  EnableWindow(param_1,0);
  while ((BVar4 = GetMessageW(&local_d8,(HWND)0x0,0,0), 0 < BVar4 &&
         (BVar4 = IsWindow(DAT_140020f00), BVar4 != 0))) {
    TranslateMessage(&local_d8);
    DispatchMessageW(&local_d8);
  }
  EnableWindow(param_1,1);
  SetForegroundWindow(param_1);
  SetFocus(param_1);
  UnregisterClassW(local_48,(HINSTANCE)local_88._8_8_);
  return;
}


```

Tóm gọi lại nó sẽ kiểm tra đối số thứ 3 là **param_3** xem nếu = 0 thì "Activation Failed" còn khác 0 thì Success. Như vậy để thành công thì mình cần làm thế nào để hàm gọi hàm ***FUN_1400017a6*** truyền vào đối số thứ 3 là một số khác 0 ví dụ như một là xong. Vì đây là một bài key gen nên ta không thể ép buộc patch chương trình. Như vậy chúng ta sẽ phải quay lại hàm trước đó để có thể xem các đoạn dẫn tới điều kiện thỏa mãn ta đã nêu.

```c
              (DAT_140020f38 == (code *)0x0) || (iVar2 = (*DAT_140020f38)(acStack_448,aRStack_348,&DAT_140016520), iVar2 != 1))
```

*DAT_140020f38 chính là dereference đến đoạn code thực thi mà chúng ta đã bảo ở bên trên với 2 tham số truyền vào lần lượt là user, serial_key và cùng với địa chỉ của vùng data ***DAT_140016520*** gồm một đống các bytes chắc để phục vụ cho việc gen key sau này. 

Các giá trị của địa chỉ ***DAT_140016520*** được quy đổi thành từng phần tử trong list:

```python
  [ 0x50, 0x13, 0x00, 0x00, 0xe9, 0x13, 0x00, 0x00, 0xfc, 0x13, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x53, 0x14, 0x00, 0x00, 0x89, 0x14, 0x00, 0x00, 0xf7, 0x14, 0x00, 0x00, 0x29, 0x15, 0x00, 0x00, 0xa0, 0x15, 0x00, 0x00, 0xdf, 0x15, 0x00, 0x00, 0x6d, 0x16, 0x00, 0x00, 0x77, 0x16, 0x00, 0x00, 0x9b, 0x16, 0x00, 0x00, 0x33, 0x17, 0x00, 0x00, 0xb8, 0x17, 0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x75, 0x18, 0x00, 0x00, 0x58, 0x18, 0x00, 0x00, 0x8d, 0x18, 0x00, 0x00, 0xf3, 0x18, 0x00, 0x00, 0x05, 0x19, 0x00, 0x00, 0x9d, 0x19, 0x00, 0x00, 0x39, 0x1a, 0x00, 0x00, 0xc8, 0x1a, 0x00, 0x00, 0xc1, 0x1a, 0x00, 0x00, 0xb9, 0x1a, 0x00, 0x00, 0x23, 0x1b, 0x00, 0x00, 0x6e, 0x1b, 0x00, 0x00, 0x9a, 0x1b, 0x00, 0x00, 0x2f, 0x1c, 0x00, 0x00, 0xbb, 0x1c, 0x00, 0x00, 0x36, 0x1d, 0x00, 0x00, 0xa8, 0x1d, 0x00, 0x00, 0x02, 0x1e, 0x00, 0x00, 0xa2, 0x1e, 0x00, 0x00, 0xff, 0x1e, 0x00, 0x00, 0x27, 0x1f, 0x00, 0x00, 0x90, 0x1f, 0x00, 0x00, 0xec, 0x1f, 0x00, 0x00, 0x1e, 0x20, 0x00, 0x00, 0xd9, 0x20, 0x00, 0x00, 0xbb, 0x20, 0x00, 0x00, 0x2d, 0x21, 0x00, 0x00, 0x2e, 0x21, 0x00, 0x00, 0xa4, 0x21, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x8d, 0x22, 0x00, 0x00, 0x66, 0x23, 0x00, 0x00, 0x9f, 0x23, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
```

Đoạn này chính là chìa khóa cuối để chúng ta có thể crack được phần mềm. Vô lại vùng nhớ chứa các mã lệnh thực thi ***DAT_140016600*** ta có psuedocode:
```c
undefined8 UndefinedFunction_140016608(char *param_1,longlong param_2,longlong param_3)

{
  int in_EAX;
  longlong lVar1;
  longlong lVar2;
  uint uVar3;
  ulonglong uVar4;
  int iVar5;
  
  if (((char)in_EAX == '\0' && in_EAX != 0) && (lVar1 = 0, param_1 != (char *)0x0)) {
    do {
      if (param_1[lVar1] == '\0') break;
      lVar1 = lVar1 + 1;
    } while (lVar1 != 0x100);
    lVar2 = 0;
    do {
      if (*(char *)(param_2 + lVar2) == '\0') {
        iVar5 = (int)lVar2;
        goto LAB_140016656;
      }
      lVar2 = lVar2 + 1;
    } while (lVar2 != 0x100);
    iVar5 = 0x100;
LAB_140016656:
    if ((iVar5 != 0) && ((int)lVar1 == 0xc)) {
      if (*param_1 != 'k') {
        return 0;
      }
      if (param_1[2] != 'a') {
        return 0;
      }
      if (param_1[4] != '3') {
        return 0;
      }
      if (param_1[6] != '3') {
        return 0;
      }
      if (param_1[8] != '5') {
        return 0;
      }
      if (param_1[10] != 'n') {
        return 0;
      }
      if (param_1[1] != 'm') {
        return 0;
      }
      if (param_1[3] != 'r') {
        return 0;
      }
      if (param_1[5] != 'v') {
        return 0;
      }
      if (param_1[7] != 'r') {
        return 0;
      }
      if (param_1[9] != '!') {
        return 0;
      }
      if (param_1[0xb] != '9') {
        return 0;
      }
      uVar4 = 0;
      uVar3 = 0x1337;
      while (uVar3 = (uint)(byte)param_1[(ulonglong)uVar3 % 0xc] +
                     ((uint)(byte)param_1[(int)((longlong)
                                                ((ulonglong)(uint)((int)uVar4 >> 0x1f) << 0x20 |
                                                uVar4 & 0xffffffff) % 0xc)] ^
                     (int)*(char *)(param_2 + uVar4) ^ uVar3),
            *(uint *)(param_3 + uVar4 * 4) == uVar3) {
        uVar4 = uVar4 + 1;
        if (iVar5 <= (int)uVar4) {
          return 1;
        }
      }
    }
  }
  return 0;
}
```

Đoạn đầu khá đơn giản, nó sẽ kiểm tra xem 2 đối số của đối số nào không chứa kí tự nào hay không, nếu 2 đối số đầu được nhập đủ thì sẽ nhảy đến ***LAB_140016656;*** để kiểm tra user và serial_key.

Trước hết đoạn code kiểm tra đối số đầu tiên (user name) với từng kí tự. Khi ghép các kí tự đó theo thức tự mảng ta được chuỗi user name đúng là  ***kmar3v3r5!n9***

Sau khi Username đúng, nó chạy vòng lặp while để kiểm tra Serial Key (param_2) dựa trên Username và Bảng dữ liệu (param_3).

```c
while (
  // BƯỚC 1: Tính toán giá trị Hash mới (uVar3 mới)
  uVar3 = Username[uVar3 % 12] + 
          (Username[uVar4 % 12] ^ SerialKey[uVar4] ^ uVar3),
  
  // BƯỚC 2: So sánh Hash mới với giá trị trong bảng dữ liệu
  *(uint *)(param_3 + uVar4 * 4) == uVar3
) { ... }
```
Như vậy ta có thể suy ra biểu thức toán học. Với uVar4 là đếm số lần lặp

- Với uVar3 = 0x1337 là hash khởi tạo
- Lấy Username[uVar3_cũ % 12]. Gọi là A.
- Lấy Username[index % 12]. Gọi là B.
- Lấy ký tự SerialKey[index]. Gọi là K.
- Tính biểu thức: New_Hash = A + (B ^ K ^ Old_Hash).
- So sánh: New_Hash phải bằng giá trị số nguyên (DWORD) tại Table[index].

Từ những logic trên ta tó thể sử dụng AI để mô phỏng lại chương trình key gen

```python
# 1. Username bắt buộc (được tìm thấy hardcoded trong shellcode)
username = b"kmar3v3r5!n9"

# 2. Giá trị Hash khởi tạo (Initial Seed)
current_hash = 0x1337

# 3. Target Hash Table (Dữ liệu bạn cung cấp từ DAT_140016520)
# Mình đã convert từ Hex Dump (Little Endian: 50 13 00 00 -> 0x1350)
target_table = [
    0x1350, 0x13E9, 0x13FC, 0x1400, 0x1453, 0x1489, 0x14F7, 0x1529, 
    0x15A0, 0x15DF, 0x166D, 0x1677, 0x169B, 0x1733, 0x17B8, 0x1803, 
    0x1875, 0x1858, 0x188D, 0x18F3, 0x1905, 0x199D, 0x1A39, 0x1AC8, 
    0x1AC1, 0x1AB9, 0x1B23, 0x1B6E, 0x1B9A, 0x1C2F, 0x1CBB, 0x1D36, 
    0x1DA8, 0x1E02, 0x1EA2, 0x1EFF, 0x1F27, 0x1F90, 0x1FEC, 0x201E, 
    0x20D9, 0x20BB, 0x212D, 0x212E, 0x21A4, 0x2200, 0x228D, 0x2366, 
    0x239F
]

serial_key = []

print("[-] Dang giai ma Serial Key...")

for i in range(len(target_table)):
    target_val = target_table[i]
    
    # Logic đảo ngược:
    # 1. Lấy ký tự A từ Username dựa trên Hash CŨ
    char_a = username[current_hash % 12]
    
    # 2. Lấy ký tự B từ Username dựa trên vị trí index hiện tại
    char_b = username[i % 12]
    
    # 3. Tính toán Key K
    # Công thức gốc: Target = A + (B ^ K ^ Old_Hash)
    # => Target - A = B ^ K ^ Old_Hash
    # => K = (Target - A) ^ B ^ Old_Hash
    
    # (Target - A) phải ép kiểu về 32-bit int để giống hành vi của C++
    term1 = (target_val - char_a) & 0xFFFFFFFF
    
    k = term1 ^ char_b ^ current_hash
    
    # Chỉ lấy byte cuối cùng (ASCII char)
    k_char = k & 0xFF
    
    serial_key.append(chr(k_char))
    
    # Cập nhật Hash cho vòng lặp tiếp theo
    current_hash = target_val

final_key = "".join(serial_key)
print(f"[+] Username: {username.decode()}")
print(f"[+] Serial Key found: {final_key}")
```
USER_NAME = "kmar3v3r5!n9"

SERIAL_KEY = "KCSC-2026-JU57-R341-UX0R-4ndd-U4DD-W!TH-U53R-N4M3"

<img width="798" height="430" alt="image" src="https://github.com/user-attachments/assets/1c52be48-7304-44e6-b6af-72de54fece93" />

Sử dụng base64 decode e lần ta sẽ được FLAG : KCSC{C0n9r4tu14t!0n5_Y0u_H4v3_Succ355fu11y_4ct!v4t4t3d_7h3_L!c3n53_S0ftw4r3_W!th_RC4_4nd_D3c0d3_Base64_3_T!m3s__=)))} 
