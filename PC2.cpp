#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <atomic>
#include <sstream>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")

static HWND g_ip{},g_pass{},g_status{},g_log{};
static SOCKET g_socket=INVALID_SOCKET;
static std::atomic<bool> g_connected{false},g_stop{false};
static void Ui(const wchar_t* s){if(g_status)SetWindowTextW(g_status,s);}
static bool SendAll(SOCKET s,const std::string&v){size_t p=0;while(p<v.size()){int n=send(s,v.data()+p,(int)(v.size()-p),0);if(n<=0)return false;p+=(size_t)n;}return true;}
static bool ReadLine(SOCKET s,std::string&out){out.clear();char c;while(out.size()<256){int n=recv(s,&c,1,0);if(n<=0)return false;if(c=='\n')return true;if(c!='\r')out+=c;}return false;}
static bool IsPrime(uint64_t n){if(n<2)return false;if(n%2==0)return n==2;for(uint64_t d=3;d<=n/d;d+=2)if(n%d==0)return false;return true;}
static uint64_t CountPrimes(uint64_t a,uint64_t b){uint64_t c=0;for(uint64_t n=a;n<=b;++n)if(IsPrime(n))++c;return c;}
static void Log(const std::wstring&s){if(!g_log)return;int n=GetWindowTextLengthW(g_log);SendMessageW(g_log,EM_SETSEL,n,n);SendMessageW(g_log,EM_REPLACESEL,FALSE,(LPARAM)(s+L"\r\n").c_str());}
static void Worker(SOCKET s){
    while(!g_stop){
        std::string line;if(!ReadLine(s,line))break;
        std::istringstream in(line);std::string cmd;uint64_t a,b;in>>cmd>>a>>b;
        if(cmd!="TASK"||!in||a<2||b<a||b>100000000){SendAll(s,"ERROR\n");continue;}
        Ui(L"PC1 передал задачу — считаю...");
        uint64_t result=CountPrimes(a,b);
        if(!SendAll(s,"RESULT "+std::to_string(result)+"\n"))break;
        std::wstringstream msg;msg<<L"Выполнено: диапазон "<<a<<L" — "<<b<<L", найдено простых: "<<result;Log(msg.str());Ui(L"Подключено. Ожидание следующей задачи...");
    }
    g_connected=false;g_socket=INVALID_SOCKET;closesocket(s);if(!g_stop)Ui(L"Соединение потеряно");
}
static void Connect(){
    if(g_connected)return;wchar_t host[256],pw[256];GetWindowTextW(g_ip,host,256);GetWindowTextW(g_pass,pw,256);
    WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Ошибка Winsock");return;}
    char h[256],p[256];WideCharToMultiByte(CP_UTF8,0,host,-1,h,256,nullptr,nullptr);WideCharToMultiByte(CP_UTF8,0,pw,-1,p,256,nullptr,nullptr);
    addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;hints.ai_protocol=IPPROTO_TCP;addrinfo*res=nullptr;
    if(getaddrinfo(h,"47821",&hints,&res)!=0){Ui(L"Неверный IP-адрес");WSACleanup();return;}
    SOCKET s=INVALID_SOCKET;for(auto*q=res;q;q=q->ai_next){s=socket(q->ai_family,q->ai_socktype,q->ai_protocol);if(s!=INVALID_SOCKET&&connect(s,q->ai_addr,(int)q->ai_addrlen)==0)break;if(s!=INVALID_SOCKET)closesocket(s);s=INVALID_SOCKET;}freeaddrinfo(res);
    if(s==INVALID_SOCKET){Ui(L"Не удалось подключиться. Проверьте IP и брандмауэр.");WSACleanup();return;}
    if(!SendAll(s,std::string("HELLO ")+p+"\n")){closesocket(s);WSACleanup();Ui(L"Ошибка авторизации");return;}
    std::string answer;if(!ReadLine(s,answer)||answer!="OK"){closesocket(s);WSACleanup();Ui(L"Пароль не принят");return;}
    g_socket=s;g_stop=false;g_connected=true;Ui(L"Подключено к PC1. Узел готов.");Log(L"Успешное подключение к координатору.");
    std::thread(Worker,s).detach();
}
static void Disconnect(){g_stop=true;if(g_socket!=INVALID_SOCKET){shutdown(g_socket,SD_BOTH);closesocket(g_socket);g_socket=INVALID_SOCKET;}g_connected=false;Ui(L"Отключено");}
static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
    switch(m){
    case WM_CREATE:
        CreateWindowW(L"STATIC",L"PC2 — вычислительный узел",WS_CHILD|WS_VISIBLE,20,15,430,28,w,nullptr,nullptr,nullptr);
        CreateWindowW(L"STATIC",L"IP компьютера PC1:",WS_CHILD|WS_VISIBLE,20,55,130,22,w,nullptr,nullptr,nullptr);
        g_ip=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"192.168.1.100",WS_CHILD|WS_VISIBLE,155,52,180,25,w,(HMENU)10,nullptr,nullptr);
        CreateWindowW(L"STATIC",L"Пароль:",WS_CHILD|WS_VISIBLE,20,88,100,22,w,nullptr,nullptr,nullptr);
        g_pass=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"change-me",WS_CHILD|WS_VISIBLE|ES_PASSWORD,155,85,180,25,w,(HMENU)11,nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"Подключиться",WS_CHILD|WS_VISIBLE,20,125,140,32,w,(HMENU)1,nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"Отключиться",WS_CHILD|WS_VISIBLE,170,125,140,32,w,(HMENU)2,nullptr,nullptr);
        g_status=CreateWindowW(L"STATIC",L"Не подключено",WS_CHILD|WS_VISIBLE,20,170,520,28,w,nullptr,nullptr,nullptr);
        g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,205,520,160,w,nullptr,nullptr,nullptr);return 0;
    case WM_COMMAND:if(LOWORD(wp)==1)std::thread(Connect).detach();if(LOWORD(wp)==2)Disconnect();return 0;
    case WM_DESTROY:Disconnect();PostQuitMessage(0);return 0;
    }return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE,PWSTR,int show){
    WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=h;wc.lpszClassName=L"PC2Window";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
    HWND w=CreateWindowW(wc.lpszClassName,L"2-PC — PC2 Worker",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,220,180,580,430,nullptr,nullptr,h,nullptr);
    if(!w)return 1;ShowWindow(w,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}