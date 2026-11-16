#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <bcrypt.h>
#include <vector>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <dxgi.h>
#include <d3d11.h>
#include <string>
#include <thread>
#include <atomic>
#include <sstream>
#include <chrono>
#include <cstdint>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"dxgi.lib")
#pragma comment(lib,"d3d11.lib")

static constexpr UINT WM_APP_STATUS=WM_APP+1,WM_APP_LOG=WM_APP+2;
static HWND g_ip{},g_pass{},g_status{},g_log{};
static SOCKET g_socket=INVALID_SOCKET;
static std::atomic<bool> g_connected{false},g_stop{false};
static void Ui(const std::wstring&s){if(g_status)PostMessageW(GetParent(g_status),WM_APP_STATUS,0,(LPARAM)new std::wstring(s));}
static void Log(const std::wstring&s){if(g_log)PostMessageW(GetParent(g_log),WM_APP_LOG,0,(LPARAM)new std::wstring(s));}

static std::string Hex(const std::vector<UCHAR>& v){static const char*d="0123456789abcdef";std::string o;o.reserve(v.size()*2);for(UCHAR c:v){o+=d[c>>4];o+=d[c&15];}return o;}
static bool Unhex(const std::string&s,std::vector<UCHAR>&o){if(s.size()%2||s.size()>128)return false;o.clear();for(size_t i=0;i<s.size();i+=2){auto cv=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};int x=cv(s[i]),y=cv(s[i+1]);if(x<0||y<0)return false;o.push_back((UCHAR)((x<<4)|y));}return true;}
static bool HmacSha256(const std::string&key,const std::vector<UCHAR>&data,std::vector<UCHAR>&out){
 BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;DWORD objLen=0,cb=0;std::vector<UCHAR>obj(1024);out.assign(32,0);
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG)<0)return false;
 bool ok=BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objLen,sizeof(objLen),&cb,0)>=0;
 if(ok){obj.resize(objLen);ok=BCryptCreateHash(alg,&hash,obj.data(),objLen,(PUCHAR)key.data(),(ULONG)key.size(),0)>=0;}
 if(ok)ok=BCryptHashData(hash,(PUCHAR)data.data(),(ULONG)data.size(),0)>=0;
 if(ok)ok=BCryptFinishHash(hash,out.data(),(ULONG)out.size(),0)>=0;
 if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return ok;
}
static bool MakeProof(const std::string&key,const std::string&nonceHex,std::string&proof){std::vector<UCHAR>nonce,mac;if(!Unhex(nonceHex,nonce)||nonce.size()!=32||!HmacSha256(key,nonce,mac))return false;proof=Hex(mac);return true;}

static void ConfigureSocket(SOCKET s){
 BOOL yes=TRUE;DWORD timeout=30000;
 setsockopt(s,SOL_SOCKET,SO_KEEPALIVE,(const char*)&yes,sizeof(yes));
 setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(const char*)&yes,sizeof(yes));
 setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
 setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout));
}
static bool SendAll(SOCKET s,const std::string&v){size_t p=0;while(p<v.size()){int n=send(s,v.data()+p,(int)(v.size()-p),0);if(n<=0)return false;p+=(size_t)n;}return true;}
static bool ReadLine(SOCKET s,std::string&out){out.clear();char c;while(out.size()<256){int n=recv(s,&c,1,0);if(n<=0)return false;if(c=='\n')return true;if(c!='\r')out+=c;}return false;}
static double CpuLoad(){
 static ULONGLONG oi=0,ok=0,ou=0;FILETIME i{},k{},u{};if(!GetSystemTimes(&i,&k,&u))return 0;
 auto cv=[](FILETIME f){ULARGE_INTEGER x{};x.LowPart=f.dwLowDateTime;x.HighPart=f.dwHighDateTime;return x.QuadPart;};
 ULONGLONG ni=cv(i),nk=cv(k),nu=cv(u);double v=0;if(ok){ULONGLONG total=(nk-ok)+(nu-ou),idle=ni-oi;if(total)v=100.0*(double)(total-idle)/(double)total;}oi=ni;ok=nk;ou=nu;return v;
}
static double MemoryLoad(){MEMORYSTATUSEX m{};m.dwLength=sizeof(m);return GlobalMemoryStatusEx(&m)?(double)m.dwMemoryLoad:0;}
static uint64_t AvailableRamMB(){MEMORYSTATUSEX m{};m.dwLength=sizeof(m);return GlobalMemoryStatusEx(&m)?m.ullAvailPhys/(1024ull*1024ull):0;}
static unsigned CpuThreads(){return GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);}
struct GpuInventory{unsigned count=0,computeCount=0;uint64_t dedicatedMB=0,sharedMB=0;};
static GpuInventory GetGpuInventory(){
 GpuInventory out;IDXGIFactory1*f=nullptr;
 if(FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1),(void**)&f)))return out;
 for(UINT i=0;;++i){IDXGIAdapter1*a=nullptr;if(f->EnumAdapters1(i,&a)==DXGI_ERROR_NOT_FOUND)break;
  DXGI_ADAPTER_DESC1 d{};if(SUCCEEDED(a->GetDesc1(&d))&&!(d.Flags&DXGI_ADAPTER_FLAG_SOFTWARE)){
   ++out.count;out.dedicatedMB+=d.DedicatedVideoMemory/(1024ull*1024ull);out.sharedMB+=d.SharedSystemMemory/(1024ull*1024ull);\n   ID3D11Device* dev=nullptr;ID3D11DeviceContext* ctx=nullptr;D3D_FEATURE_LEVEL obtained{};const D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_1,D3D_FEATURE_LEVEL_10_0};\n   if(SUCCEEDED(D3D11CreateDevice(a,D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,(UINT)_countof(levels),D3D11_SDK_VERSION,&dev,&obtained,&ctx))){if(obtained>=D3D_FEATURE_LEVEL_11_0)++out.computeCount;if(ctx)ctx->Release();if(dev)dev->Release();}
  }a->Release();
 }f->Release();return out;
}
static std::string MakeHeartbeat(){
 auto g=GetGpuInventory();std::ostringstream hb;hb<<"HB "<<CpuLoad()<<" "<<MemoryLoad()<<" "<<CpuThreads()<<" "<<AvailableRamMB()<<" "<<g.count<<" "<<g.dedicatedMB<<" "<<g.sharedMB<<"\n";return hb.str();
}
static uint64_t CountPrimes(uint64_t a,uint64_t b){
 if(b<a||b<2)return 0;a=std::max<uint64_t>(a,2);
 uint64_t root=1;while(root+1<=b/(root+1))++root;
 std::vector<uint8_t> baseMark((size_t)root+1,1);std::vector<uint32_t> primes;
 for(uint64_t p=2;p<=root;++p)if(baseMark[(size_t)p]){
  primes.push_back((uint32_t)p);
  if(p<=root/p)for(uint64_t q=p*p;q<=root;q+=p)baseMark[(size_t)q]=0;
 }
 constexpr uint64_t BLOCK=1u<<20;uint64_t total=0;
 for(uint64_t low=a;low<=b;){
  uint64_t high=std::min<uint64_t>(b,low+BLOCK-1);std::vector<uint8_t> mark((size_t)(high-low+1),1);
  for(uint64_t p:primes){
   if(p>high/p)break;
   uint64_t first=(low/p)*p;if(first<low)first+=p;
   uint64_t square=p*p;if(first<square)first=square;
   for(uint64_t n=first;n<=high;n+=p)mark[(size_t)(n-low)]=0;
  }
  for(uint8_t v:mark)total+=v!=0;
  if(high==b)break;low=high+1;
 }
 return total;
}
static void Worker(SOCKET s){
 auto last=std::chrono::steady_clock::now();
 while(!g_stop){
  fd_set set;FD_ZERO(&set);FD_SET(s,&set);timeval tv{1,0};int ready=select(0,&set,nullptr,nullptr,&tv);
  if(ready==SOCKET_ERROR)break;
  if(ready==0){if(!SendAll(s,MakeHeartbeat()))break;continue;}
  std::string line;if(!ReadLine(s,line))break;
  std::istringstream in(line);std::string cmd,kind;uint64_t a=0,b=0;in>>cmd>>kind>>a>>b;
  if(cmd!="TASK"||kind!="PRIME"||!in||a<2||b<a||b>50000000){if(!SendAll(s,"ERROR\n"))break;continue;}
  Ui(L"Получена задача. Выполняю вычисления...");
  auto started=std::chrono::steady_clock::now();uint64_t result=CountPrimes(a,b);
  auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
  if(!SendAll(s,"RESULT "+std::to_string(result)+"\n"))break;
  std::wstringstream msg;msg<<L"Задача выполнена: "<<a<<L"–"<<b<<L"; найдено "<<result<<L"; "<<elapsed<<L" мс.";Log(msg.str());Ui(L"Подключено. Ожидаю задачи.");
 }
 g_connected=false;g_socket=INVALID_SOCKET;closesocket(s);if(!g_stop)Ui(L"Связь потеряна. Переподключитесь.");WSACleanup();
}
static bool DiscoverPC1(std::string& found){
 SOCKET d=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(d==INVALID_SOCKET)return false;
 BOOL yes=TRUE;setsockopt(d,SOL_SOCKET,SO_BROADCAST,(const char*)&yes,sizeof(yes));
 DWORD bytes=15000;std::vector<unsigned char> storage(bytes);
 IP_ADAPTER_ADDRESSES* first=(IP_ADAPTER_ADDRESSES*)storage.data();
 ULONG rc=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,first,&bytes);
 if(rc==ERROR_BUFFER_OVERFLOW){storage.resize(bytes);first=(IP_ADAPTER_ADDRESSES*)storage.data();rc=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,first,&bytes);}
 if(rc==NO_ERROR)for(auto*ad=first;ad;ad=ad->Next){
  if(ad->OperStatus!=IfOperStatusUp)continue;
  for(auto*u=ad->FirstUnicastAddress;u;u=u->Next){
   if(!u->Address.lpSockaddr||u->Address.lpSockaddr->sa_family!=AF_INET)continue;
   auto*ip=(sockaddr_in*)u->Address.lpSockaddr;uint32_t host=ntohl(ip->sin_addr.s_addr);
   if((host>>24)==127)continue;unsigned prefix=u->OnLinkPrefixLength;if(prefix>32)continue;
   uint32_t mask=prefix==0?0u:(0xffffffffu<<(32-prefix));
   sockaddr_in target{};target.sin_family=AF_INET;target.sin_port=htons(47820);target.sin_addr.s_addr=htonl((host&mask)|(~mask));
   const char msg[]="2PC_DISCOVER_V1";sendto(d,msg,(int)sizeof(msg)-1,0,(sockaddr*)&target,sizeof(target));
  }
 }
 auto until=std::chrono::steady_clock::now()+std::chrono::seconds(4);
 while(std::chrono::steady_clock::now()<until){
  fd_set set;FD_ZERO(&set);FD_SET(d,&set);timeval tv{0,300000};int ready=select(0,&set,nullptr,nullptr,&tv);
  if(ready>0){char buf[64]{};sockaddr_in peer{};int len=sizeof(peer);int n=recvfrom(d,buf,sizeof(buf)-1,0,(sockaddr*)&peer,&len);
   if(n>0&&std::string(buf,n)=="2PC1_V1 47821"){char ip[INET_ADDRSTRLEN]{};if(inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip))){found=ip;closesocket(d);return true;}}
  }
 }
 closesocket(d);return false;
}
static void Connect(){
 if(g_connected)return;wchar_t host[256]{},pw[256]{};GetWindowTextW(g_ip,host,256);GetWindowTextW(g_pass,pw,256);
 if(wcslen(pw)<8){Ui(L"Введите пароль не короче 8 символов");return;}
 WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Ошибка Winsock");return;}
 if(!host[0]||_wcsicmp(host,L"AUTO")==0){std::string found;Ui(L"Автоматически ищу PC1 по Ethernet...");
  if(!DiscoverPC1(found)){WSACleanup();Ui(L"PC1 не найден. Проверьте кабель и запущенный сервер.");return;}
  MultiByteToWideChar(CP_UTF8,0,found.c_str(),-1,host,256);SetWindowTextW(g_ip,host);
 }
 char h[256]{},p[256]{};WideCharToMultiByte(CP_UTF8,0,host,-1,h,256,nullptr,nullptr);WideCharToMultiByte(CP_UTF8,0,pw,-1,p,256,nullptr,nullptr);
 addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;hints.ai_protocol=IPPROTO_TCP;addrinfo*res=nullptr;
 if(getaddrinfo(h,"47821",&hints,&res)!=0){Ui(L"Неверный IP");WSACleanup();return;}
 SOCKET s=INVALID_SOCKET;for(auto*q=res;q;q=q->ai_next){s=socket(q->ai_family,q->ai_socktype,q->ai_protocol);if(s!=INVALID_SOCKET&&connect(s,q->ai_addr,(int)q->ai_addrlen)==0)break;if(s!=INVALID_SOCKET)closesocket(s);s=INVALID_SOCKET;}freeaddrinfo(res);
 if(s==INVALID_SOCKET){Ui(L"Не удалось подключиться. Проверьте IP и брандмауэр.");WSACleanup();return;}ConfigureSocket(s);
 std::string answer;if(!ReadLine(s,answer)||answer.rfind("CHALLENGE ",0)!=0){closesocket(s);WSACleanup();Ui(L"Сервер не прошёл проверку протокола");return;}
 std::string proof;if(!MakeProof(p,answer.substr(10),proof)||!SendAll(s,"AUTH "+proof+"\n")||!ReadLine(s,answer)||answer!="OK"){closesocket(s);WSACleanup();Ui(L"Пароль не принят или проверка не пройдена");return;}
 g_socket=s;g_stop=false;g_connected=true;Ui(L"Подключено. Отправляю показатели загрузки PC2.");Log(L"Авторизация успешна.");std::thread(Worker,s).detach();
}
static void Disconnect(){g_stop=true;SOCKET s=g_socket;g_socket=INVALID_SOCKET;g_connected=false;if(s!=INVALID_SOCKET){shutdown(s,SD_BOTH);closesocket(s);}Ui(L"Отключено");}
static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
 if(m==WM_APP_STATUS){auto*p=(std::wstring*)lp;SetWindowTextW(g_status,p->c_str());delete p;return 0;}
 if(m==WM_APP_LOG){auto*p=(std::wstring*)lp;int n=GetWindowTextLengthW(g_log);SendMessageW(g_log,EM_SETSEL,n,n);SendMessageW(g_log,EM_REPLACESEL,FALSE,(LPARAM)(*p+L"\r\n").c_str());delete p;return 0;}
 switch(m){
 case WM_CREATE:
  CreateWindowW(L"STATIC",L"PC2 — адаптивный вычислительный узел",WS_CHILD|WS_VISIBLE,20,15,500,25,w,nullptr,nullptr,nullptr);
  CreateWindowW(L"STATIC",L"IP PC1 (AUTO — поиск по Ethernet):",WS_CHILD|WS_VISIBLE,20,53,130,22,w,nullptr,nullptr,nullptr);
  g_ip=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"AUTO",WS_CHILD|WS_VISIBLE,155,50,200,25,w,(HMENU)10,nullptr,nullptr);
  CreateWindowW(L"STATIC",L"Общий пароль:",WS_CHILD|WS_VISIBLE,20,88,120,22,w,nullptr,nullptr,nullptr);
  g_pass=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"change-this-password",WS_CHILD|WS_VISIBLE|ES_PASSWORD,155,85,200,25,w,(HMENU)11,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Подключиться",WS_CHILD|WS_VISIBLE,20,125,140,32,w,(HMENU)1,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Отключиться",WS_CHILD|WS_VISIBLE,170,125,140,32,w,(HMENU)2,nullptr,nullptr);
  g_status=CreateWindowW(L"STATIC",L"Не подключено",WS_CHILD|WS_VISIBLE,20,170,540,35,w,nullptr,nullptr,nullptr);
  g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,212,540,178,w,nullptr,nullptr,nullptr);return 0;
 case WM_COMMAND:if(LOWORD(wp)==1)std::thread(Connect).detach();if(LOWORD(wp)==2)Disconnect();return 0;
 case WM_DESTROY:Disconnect();PostQuitMessage(0);return 0;
 }return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE,PWSTR,int show){
 WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=h;wc.lpszClassName=L"TwoPC_PC2";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
 HWND w=CreateWindowW(wc.lpszClassName,L"2-PC — PC2",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,200,160,600,450,nullptr,nullptr,h,nullptr);
 if(!w)return 1;ShowWindow(w,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}