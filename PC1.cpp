#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <vector>
#include <windows.h>
#include <ws2tcpip.h>
#include <dxgi.h>
#include <d3d11.h>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <tlhelp32.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dxgi.lib")
#pragma comment(lib,"d3d11.lib")

static constexpr unsigned short PORT=47821;
static constexpr uint64_t TEST_END=3000000;
static constexpr UINT WM_APP_STATUS=WM_APP+1, WM_APP_LOG=WM_APP+2;
static HWND g_status{},g_log{};
static SOCKET g_client=INVALID_SOCKET,g_listener=INVALID_SOCKET;
static std::mutex g_sockMutex;
static std::atomic<bool> g_running{false},g_connected{false},g_taskActive{false};
static std::atomic<double> g_remoteCpu{45.0},g_remoteMem{0.0};
static std::atomic<uint64_t> g_remoteRamMB{0},g_remoteVramMB{0},g_remoteSharedGpuMB{0};
static std::atomic<unsigned> g_remoteThreads{0},g_remoteGpuCount{0},g_remoteComputeGpuCount{0};

static void Ui(const std::wstring&s){if(g_status)PostMessageW(GetParent(g_status),WM_APP_STATUS,0,(LPARAM)new std::wstring(s));}
static void Log(const std::wstring&s){if(g_log)PostMessageW(GetParent(g_log),WM_APP_LOG,0,(LPARAM)new std::wstring(s));}

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
 static ULONGLONG oldIdle=0,oldKernel=0,oldUser=0; FILETIME i{},k{},u{};
 if(!GetSystemTimes(&i,&k,&u))return 0;
 auto cv=[](FILETIME f){ULARGE_INTEGER x{};x.LowPart=f.dwLowDateTime;x.HighPart=f.dwHighDateTime;return x.QuadPart;};
 ULONGLONG ni=cv(i),nk=cv(k),nu=cv(u);double result=0;
 if(oldKernel){ULONGLONG total=(nk-oldKernel)+(nu-oldUser),idle=ni-oldIdle;if(total)result=100.0*(double)(total-idle)/(double)total;}
 oldIdle=ni;oldKernel=nk;oldUser=nu;return std::clamp(result,0.0,100.0);
}
static double MemoryLoad(){MEMORYSTATUSEX m{};m.dwLength=sizeof(m);return GlobalMemoryStatusEx(&m)?(double)m.dwMemoryLoad:0.0;}
static uint64_t AvailableRamMB(){MEMORYSTATUSEX m{};m.dwLength=sizeof(m);return GlobalMemoryStatusEx(&m)?m.ullAvailPhys/(1024ull*1024ull):0;}
static unsigned CpuThreads(){return GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);}
struct GpuInventory{unsigned count=0,computeCount=0;uint64_t dedicatedMB=0,sharedMB=0;};
static GpuInventory GetGpuInventory(){
 GpuInventory out;IDXGIFactory1*f=nullptr;
 if(FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1),(void**)&f)))return out;
 for(UINT i=0;;++i){IDXGIAdapter1*a=nullptr;if(f->EnumAdapters1(i,&a)==DXGI_ERROR_NOT_FOUND)break;
  DXGI_ADAPTER_DESC1 d{};if(SUCCEEDED(a->GetDesc1(&d))&&!(d.Flags&DXGI_ADAPTER_FLAG_SOFTWARE)){
   ++out.count;out.dedicatedMB+=d.DedicatedVideoMemory/(1024ull*1024ull);out.sharedMB+=d.SharedSystemMemory/(1024ull*1024ull);
   ID3D11Device* dev=nullptr;ID3D11DeviceContext* ctx=nullptr;D3D_FEATURE_LEVEL obtained{};const D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_1,D3D_FEATURE_LEVEL_10_0};
   if(SUCCEEDED(D3D11CreateDevice(a,D3D_DRIVER_TYPE_UNKNOWN,nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,(UINT)_countof(levels),D3D11_SDK_VERSION,&dev,&obtained,&ctx))){if(obtained>=D3D_FEATURE_LEVEL_11_0)++out.computeCount;if(ctx)ctx->Release();if(dev)dev->Release();}
  }a->Release();
 }f->Release();return out;
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
static void DiscoveryLoop(){
 WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0)return;
 SOCKET d=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(d==INVALID_SOCKET){WSACleanup();return;}
 BOOL yes=TRUE;setsockopt(d,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
 sockaddr_in bindAddr{};bindAddr.sin_family=AF_INET;bindAddr.sin_port=htons(47820);bindAddr.sin_addr.s_addr=htonl(INADDR_ANY);
 if(bind(d,(sockaddr*)&bindAddr,sizeof(bindAddr))==SOCKET_ERROR){closesocket(d);WSACleanup();return;}
 while(g_running){
  fd_set set;FD_ZERO(&set);FD_SET(d,&set);timeval tv{1,0};int ready=select(0,&set,nullptr,nullptr,&tv);
  if(ready<=0)continue;
  char buf[64]{};sockaddr_in peer{};int len=sizeof(peer);
  int n=recvfrom(d,buf,sizeof(buf)-1,0,(sockaddr*)&peer,&len);
  if(n<=0)continue;buf[n]=0;
  if(std::string(buf,n)=="2PC_DISCOVER_V1"){
   const char reply[]="2PC1_V1 47821";
   sendto(d,reply,(int)sizeof(reply)-1,0,(sockaddr*)&peer,len);
  }
 }
 closesocket(d);WSACleanup();
}
static void ServerLoop(){
 WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Winsock не запустился");g_running=false;return;}
 SOCKET ls=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(ls==INVALID_SOCKET){Ui(L"Не удалось создать сокет");WSACleanup();g_running=false;return;}
 g_listener=ls;BOOL yes=TRUE;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
 sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(PORT);addr.sin_addr.s_addr=htonl(INADDR_ANY);
 if(bind(ls,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR||listen(ls,1)==SOCKET_ERROR){Ui(L"Порт 47821 занят или заблокирован");closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();g_running=false;return;}
 Ui(L"Сервер запущен. Ожидаю PC2; включено автообнаружение по Ethernet.");
 std::thread discovery(DiscoveryLoop);
 while(g_running){
  SOCKET c=accept(ls,nullptr,nullptr);if(c==INVALID_SOCKET){if(!g_running)break;continue;}ConfigureSocket(c);
  std::string line;
  {std::lock_guard<std::mutex>lk(g_sockMutex);g_client=c;}
  g_connected=true;Ui(L"PC2 подключён напрямую по Ethernet");Log(L"PC2 подключён без парольной авторизации.");
  while(g_running&&g_connected){
   if(g_taskActive){std::this_thread::sleep_for(std::chrono::milliseconds(100));continue;}
   fd_set set;FD_ZERO(&set);FD_SET(c,&set);timeval tv{1,0};int ready=select(0,&set,nullptr,nullptr,&tv);
   if(ready==SOCKET_ERROR)break;
   if(ready>0){if(!ReadLine(c,line))break;std::istringstream in(line);std::string cmd;double cpu,mem;in>>cmd>>cpu>>mem;if(cmd=="HB"&&in){unsigned threads=0,gpus=0;uint64_t ram=0,vram=0,shared=0;in>>threads>>ram>>gpus>>vram>>shared;unsigned computeGpus=0;in>>computeGpus;g_remoteComputeGpuCount=computeGpus;g_remoteCpu=std::clamp(cpu,0.0,100.0);g_remoteMem=std::clamp(mem,0.0,100.0);g_remoteThreads=threads;g_remoteRamMB=ram;g_remoteGpuCount=gpus;g_remoteVramMB=vram;g_remoteSharedGpuMB=shared;}}
  }
  {std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client==c)g_client=INVALID_SOCKET;}
  closesocket(c);g_connected=false;Ui(L"PC2 отключён. Ожидаю повторное подключение.");Log(L"Соединение с PC2 закрыто.");
 }
 if(discovery.joinable())discovery.join();
 if(ls!=INVALID_SOCKET)closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();g_running=false;Ui(L"Сервер остановлен");
}
static bool IsGameForeground(){
 HWND fg=GetForegroundWindow();if(!fg)return false;DWORD pid=0;GetWindowThreadProcessId(fg,&pid);if(!pid)return false;
 HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!h)return false;
 wchar_t path[1024]{};DWORD size=(DWORD)_countof(path);BOOL ok=QueryFullProcessImageNameW(h,0,path,&size);CloseHandle(h);if(!ok)return false;
 const wchar_t* name=wcsrchr(path,L'\\');name=name?name+1:path;
 static const wchar_t* games[]={L"BlackDesert64.exe",L"BlackDesert32.exe",L"BlackDesert.exe",L"javaw.exe",L"Minecraft.Windows.exe",L"Minecraft.exe",L"Cyberpunk2077.exe",L"Starfield.exe",L"eldenring.exe",L"TslGame.exe",L"r5apex.exe",L"GenshinImpact.exe",L"dota2.exe",L"cs2.exe"};
 for(const auto* game:games)if(_wcsicmp(name,game)==0)return true;
 return false;
}
static void RunDistributedTest(){
 SOCKET s;{std::lock_guard<std::mutex>lk(g_sockMutex);s=g_client;}
 if(!g_connected||s==INVALID_SOCKET){MessageBoxW(nullptr,L"Сначала подключите PC2.",L"Нет вычислительного узла",MB_ICONWARNING);return;}
 CpuLoad();std::this_thread::sleep_for(std::chrono::milliseconds(250));double localCpu=CpuLoad();double remoteCpu=g_remoteCpu.load();
 double localMem=MemoryLoad(),remoteMem=g_remoteMem.load();
 bool gameForeground=IsGameForeground();
 double localFree=std::max(0.02,1.0-localCpu/100.0)*std::max(0.05,1.0-localMem/100.0)*std::max(1u,CpuThreads());
 double remoteFree=std::max(0.02,1.0-remoteCpu/100.0)*std::max(0.05,1.0-remoteMem/100.0)*std::max(1u,g_remoteThreads.load());
 double remoteShare=remoteFree/(localFree+remoteFree);
 if(remoteCpu>92.0||remoteMem>94.0)remoteShare=0.0;
 remoteShare=std::clamp(remoteShare,0.0,0.95);
 if(gameForeground&&remoteCpu<90.0&&remoteMem<92.0)remoteShare=1.0;
 if(remoteShare<=0.001){
  if(gameForeground){Ui(L"PC2 сейчас перегружен. Вычисление отложено, чтобы не мешать игре на PC1.");return;}
  auto t0=std::chrono::steady_clock::now();uint64_t localOnly=CountPrimes(2,TEST_END);
  auto dt=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  std::wstringstream msg;msg<<L"PC2 перегружен; задача выполнена локально: "<<localOnly<<L", время="<<dt<<L" мс.";
  Ui(msg.str());Log(msg.str());return;
 }
 uint64_t startN=2,span=TEST_END-startN+1;
 uint64_t remoteCount=(uint64_t)(span*remoteShare);
 uint64_t split=TEST_END-remoteCount;
 if(split<startN)split=startN;
 g_taskActive=true;Ui(gameForeground?L"Обнаружена игра на PC1: локальную вычислительную нагрузку переношу на PC2.":L"Распределяю задачу по свободным CPU-потокам...");
 auto started=std::chrono::steady_clock::now();
 if(!SendAll(s,"TASK PRIME "+std::to_string(split+1)+" "+std::to_string(TEST_END)+"\n")){g_taskActive=false;Ui(L"Не удалось отправить задачу PC2");return;}
 uint64_t local=CountPrimes(startN,split);
 std::string answer;bool received=false;
 while(g_running&&g_connected){if(!ReadLine(s,answer))break;if(answer.rfind("HB ",0)==0){std::istringstream hb(answer);std::string tag;double cpu,mem;hb>>tag>>cpu>>mem;if(hb){unsigned threads=0,gpus=0;uint64_t ram=0,vram=0,shared=0;hb>>threads>>ram>>gpus>>vram>>shared;unsigned computeGpus=0;hb>>computeGpus;g_remoteComputeGpuCount=computeGpus;g_remoteCpu=std::clamp(cpu,0.0,100.0);g_remoteMem=std::clamp(mem,0.0,100.0);g_remoteThreads=threads;g_remoteRamMB=ram;g_remoteGpuCount=gpus;g_remoteVramMB=vram;g_remoteSharedGpuMB=shared;}continue;}received=true;break;}
 g_taskActive=false;
 if(!received||answer.rfind("RESULT ",0)!=0){Ui(L"PC2 не вернул результат. Проверьте соединение.");return;}
 uint64_t remote=0;try{remote=std::stoull(answer.substr(7));}catch(...){Ui(L"Некорректный ответ PC2");return;}
 auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
 auto localGpu=GetGpuInventory();std::wstringstream out;out<<L"Тест завершён: PC1="<<local<<L", PC2="<<remote<<L", всего="<<(local+remote)<<L". Доля PC2="<<(int)(remoteShare*100)<<L"%, CPU PC1="<<(int)localCpu<<L"%/"<<CpuThreads()<<L" потоков, PC2="<<(int)remoteCpu<<L"%/"<<g_remoteThreads.load()<<L" потоков, RAM доступно PC1="<<AvailableRamMB()<<L" МБ, PC2="<<g_remoteRamMB.load()<<L" МБ, GPU PC1="<<localGpu.count<<L" ("<<localGpu.dedicatedMB<<L" МБ VRAM), PC2="<<g_remoteGpuCount.load()<<L" ("<<g_remoteVramMB.load()<<L" МБ VRAM, D3D11 compute="<<g_remoteComputeGpuCount.load()<<L"), время="<<ms<<L" мс.";
 Ui(out.str());Log(out.str());
}
static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
 if(m==WM_APP_STATUS){auto*p=(std::wstring*)lp;SetWindowTextW(g_status,p->c_str());delete p;return 0;}
 if(m==WM_APP_LOG){auto*p=(std::wstring*)lp;int n=GetWindowTextLengthW(g_log);SendMessageW(g_log,EM_SETSEL,n,n);SendMessageW(g_log,EM_REPLACESEL,FALSE,(LPARAM)(*p+L"\r\n").c_str());delete p;return 0;}
 switch(m){
 case WM_CREATE:
  CreateWindowW(L"STATIC",L"PC1 — координатор и адаптивный планировщик",WS_CHILD|WS_VISIBLE,20,15,500,25,w,nullptr,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Запустить сервер",WS_CHILD|WS_VISIBLE,20,55,140,32,w,(HMENU)1,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Остановить",WS_CHILD|WS_VISIBLE,170,55,110,32,w,(HMENU)2,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Тест распределения",WS_CHILD|WS_VISIBLE,290,55,170,32,w,(HMENU)3,nullptr,nullptr);
  g_status=CreateWindowW(L"STATIC",L"Сервер не запущен",WS_CHILD|WS_VISIBLE,20,102,540,35,w,nullptr,nullptr,nullptr);
  g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,145,540,245,w,nullptr,nullptr,nullptr);return 0;
 case WM_COMMAND:
  if(LOWORD(wp)==1&&!g_running){g_running=true;std::thread(ServerLoop).detach();}
  if(LOWORD(wp)==2&&g_running){g_running=false;if(g_listener!=INVALID_SOCKET){shutdown(g_listener,SD_BOTH);closesocket(g_listener);}std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client!=INVALID_SOCKET){shutdown(g_client,SD_BOTH);closesocket(g_client);g_client=INVALID_SOCKET;}g_connected=false;}
  if(LOWORD(wp)==3)std::thread(RunDistributedTest).detach();return 0;
 case WM_DESTROY:
  g_running=false;if(g_listener!=INVALID_SOCKET){shutdown(g_listener,SD_BOTH);closesocket(g_listener);}
  {std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client!=INVALID_SOCKET){shutdown(g_client,SD_BOTH);closesocket(g_client);g_client=INVALID_SOCKET;}}
  PostQuitMessage(0);return 0;
 }return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE,PWSTR,int show){
 WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=h;wc.lpszClassName=L"TwoPC_PC1";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
 HWND w=CreateWindowW(wc.lpszClassName,L"2-PC — PC1",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,180,140,600,450,nullptr,nullptr,h,nullptr);
 if(!w)return 1;ShowWindow(w,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}