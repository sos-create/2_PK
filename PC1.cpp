#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <sstream>
#include <vector>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")

static constexpr int PORT = 47821;
static HWND g_status{}, g_password{}, g_log{};
static SOCKET g_client = INVALID_SOCKET, g_listener = INVALID_SOCKET;
static std::mutex g_sockMutex;
static std::atomic<bool> g_running{false}, g_connected{false};
static std::wstring g_pass = L"change-me";

static void Ui(const wchar_t* s) { if (g_status) SetWindowTextW(g_status, s); }
static bool SendAll(SOCKET s, const std::string& v) {
    size_t p=0; while(p<v.size()){ int n=send(s,v.data()+p,(int)(v.size()-p),0); if(n<=0)return false; p+=(size_t)n;} return true;
}
static bool ReadLine(SOCKET s, std::string& out) {
    out.clear(); char c;
    while(out.size()<256){ int n=recv(s,&c,1,0); if(n<=0)return false; if(c=='\n')return true; if(c!='\r')out+=c; }
    return false;
}
static bool IsPrime(uint64_t n) {
    if(n<2)return false; if(n%2==0)return n==2;
    for(uint64_t d=3;d<=n/d;d+=2)if(n%d==0)return false; return true;
}
static uint64_t CountPrimes(uint64_t a,uint64_t b) {
    uint64_t count=0; for(uint64_t n=a;n<=b;++n)if(IsPrime(n))++count; return count;
}
static void Log(const std::wstring& s) {
    if(!g_log)return; int len=GetWindowTextLengthW(g_log); SendMessageW(g_log,EM_SETSEL,len,len);
    SendMessageW(g_log,EM_REPLACESEL,FALSE,(LPARAM)(s+L"\r\n").c_str());
}
static void ServerLoop() {
    WSADATA wd{}; if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Ошибка запуска Winsock");return;}
    SOCKET ls=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); if(ls==INVALID_SOCKET){Ui(L"Не удалось создать сокет");WSACleanup();return;}
    g_listener=ls; BOOL yes=TRUE; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
    sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons(PORT); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(ls,(sockaddr*)&a,sizeof(a))==SOCKET_ERROR||listen(ls,1)==SOCKET_ERROR){Ui(L"Не удалось открыть порт 47821");closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();return;}
    Ui(L"Ожидание PC2 на порту 47821...");
    while(g_running){
        SOCKET c=accept(ls,nullptr,nullptr); if(c==INVALID_SOCKET){if(!g_running)break;continue;}
        std::string line; std::string expected;
        int plen=WideCharToMultiByte(CP_UTF8,0,g_pass.c_str(),-1,nullptr,0,nullptr,nullptr);
        if(plen>1){expected.resize(plen);WideCharToMultiByte(CP_UTF8,0,g_pass.c_str(),-1,expected.data(),plen,nullptr,nullptr);expected.resize(plen-1);}
        if(!ReadLine(c,line)||line!="HELLO "+expected||!SendAll(c,"OK\n")){closesocket(c);continue;}
        {std::lock_guard<std::mutex> lk(g_sockMutex); if(g_client!=INVALID_SOCKET)closesocket(g_client);g_client=c;}
        g_connected=true; Ui(L"PC2 подключён — готов к вычислениям"); Log(L"PC2 прошёл авторизацию.");
        while(g_running&&g_connected){
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if(g_client!=c)break;
        }
        {std::lock_guard<std::mutex> lk(g_sockMutex);if(g_client==c)g_client=INVALID_SOCKET;}
        closesocket(c);g_connected=false;Ui(L"PC2 отключён. Ожидание подключения...");
    }
    if(ls!=INVALID_SOCKET)closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();Ui(L"Сервер остановлен");
}
static void RunBenchmark() {
    SOCKET s; {std::lock_guard<std::mutex> lk(g_sockMutex);s=g_client;}
    if(!g_connected||s==INVALID_SOCKET){MessageBoxW(nullptr,L"Сначала подключите PC2.",L"Нет узла",MB_ICONWARNING);return;}
    Ui(L"Выполняется распределённая задача...");
    const uint64_t mid=1500000, end=3000000;
    if(!SendAll(s,"TASK "+std::to_string(mid+1)+" "+std::to_string(end)+"\n")){Ui(L"Ошибка отправки задачи");return;}
    auto start=GetTickCount64();
    uint64_t local=CountPrimes(2,mid);
    std::string answer;
    if(!ReadLine(s,answer)||answer.rfind("RESULT ",0)!=0){Ui(L"PC2 не вернул корректный результат");return;}
    uint64_t remote=0; try{remote=std::stoull(answer.substr(7));}catch(...){Ui(L"Ошибка формата результата");return;}
    auto ms=GetTickCount64()-start;
    std::wstringstream out;out<<L"Готово. PC1: "<<local<<L"; PC2: "<<remote<<L"; всего: "<<(local+remote)<<L"; время: "<<ms<<L" мс.";
    Ui(out.str().c_str());Log(out.str());
}
static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
    switch(m){
    case WM_CREATE:{
        CreateWindowW(L"STATIC",L"PC1 — координатор вычислений",WS_CHILD|WS_VISIBLE,20,15,430,28,w,nullptr,nullptr,nullptr);
        CreateWindowW(L"STATIC",L"Общий пароль:",WS_CHILD|WS_VISIBLE,20,55,100,22,w,nullptr,nullptr,nullptr);
        g_password=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"change-me",WS_CHILD|WS_VISIBLE|ES_PASSWORD,125,52,180,25,w,(HMENU)10,nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"Запустить сервер",WS_CHILD|WS_VISIBLE,20,92,140,32,w,(HMENU)1,nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"Остановить",WS_CHILD|WS_VISIBLE,170,92,110,32,w,(HMENU)2,nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"Тест распределения",WS_CHILD|WS_VISIBLE,290,92,160,32,w,(HMENU)3,nullptr,nullptr);
        g_status=CreateWindowW(L"STATIC",L"Сервер не запущен",WS_CHILD|WS_VISIBLE,20,140,520,28,w,nullptr,nullptr,nullptr);
        g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,175,520,190,w,nullptr,nullptr,nullptr);
        return 0;}
    case WM_COMMAND:
        if(LOWORD(wp)==1&&!g_running){wchar_t b[256];GetWindowTextW(g_password,b,256);g_pass=b;g_running=true;std::thread(ServerLoop).detach();}
        if(LOWORD(wp)==2&&g_running){g_running=false;if(g_listener!=INVALID_SOCKET)closesocket(g_listener);{std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client!=INVALID_SOCKET){shutdown(g_client,SD_BOTH);closesocket(g_client);g_client=INVALID_SOCKET;}}g_connected=false;}
        if(LOWORD(wp)==3)std::thread(RunBenchmark).detach();
        return 0;
    case WM_DESTROY:g_running=false;if(g_listener!=INVALID_SOCKET)closesocket(g_listener);{std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client!=INVALID_SOCKET){shutdown(g_client,SD_BOTH);closesocket(g_client);g_client=INVALID_SOCKET;}}PostQuitMessage(0);return 0;
    }return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE, PWSTR,int show){
    WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=h;wc.lpszClassName=L"PC1Window";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
    HWND w=CreateWindowW(wc.lpszClassName,L"2-PC — PC1 Coordinator",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,200,160,580,430,nullptr,nullptr,h,nullptr);
    if(!w)return 1;ShowWindow(w,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}