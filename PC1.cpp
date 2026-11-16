#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <bcrypt.h>
#include <vector>
#include <windows.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <mutex>
#include <memory>
#include <condition_variable>
#include <atomic>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <algorithm>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"bcrypt.lib")

static constexpr unsigned short PORT=47821;
static constexpr uint64_t TEST_END=3000000;
static constexpr UINT WM_APP_STATUS=WM_APP+1, WM_APP_LOG=WM_APP+2;
static HWND g_status{},g_password{},g_log{};
static SOCKET g_listener=INVALID_SOCKET;
struct WorkerSession {
 SOCKET socket=INVALID_SOCKET; std::atomic<bool> alive{true};
 std::atomic<double> cpu{50.0},mem{0.0};
 std::mutex sendMutex,resultMutex; std::condition_variable resultCv;
 uint64_t result=0; bool resultReady=false;
};
static std::mutex g_workersMutex;
static std::vector<std::shared_ptr<WorkerSession>> g_workers;
static std::atomic<bool> g_running{false},g_connected{false},g_taskActive{false};
static std::atomic<int> g_handlerCount{0};
static std::wstring g_pass=L"change-this-password";

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
 static ULONGLONG oldIdle=0,oldKernel=0,oldUser=0; FILETIME i{},k{},u{};
 if(!GetSystemTimes(&i,&k,&u))return 0;
 auto cv=[](FILETIME f){ULARGE_INTEGER x{};x.LowPart=f.dwLowDateTime;x.HighPart=f.dwHighDateTime;return x.QuadPart;};
 ULONGLONG ni=cv(i),nk=cv(k),nu=cv(u);double result=0;
 if(oldKernel){ULONGLONG total=(nk-oldKernel)+(nu-oldUser),idle=ni-oldIdle;if(total)result=100.0*(double)(total-idle)/(double)total;}
 oldIdle=ni;oldKernel=nk;oldUser=nu;return std::clamp(result,0.0,100.0);
}
static double MemoryLoad(){MEMORYSTATUSEX m{};m.dwLength=sizeof(m);return GlobalMemoryStatusEx(&m)?(double)m.dwMemoryLoad:0.0;}
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
static void WorkerSessionLoop(SOCKET c){
 std::string expected,line;int n=WideCharToMultiByte(CP_UTF8,0,g_pass.c_str(),-1,nullptr,0,nullptr,nullptr);
 if(n>1){expected.resize(n);WideCharToMultiByte(CP_UTF8,0,g_pass.c_str(),-1,expected.data(),n,nullptr,nullptr);expected.resize(n-1);}
 std::vector<UCHAR> nonce(32);if(BCryptGenRandom(nullptr,nonce.data(),(ULONG)nonce.size(),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0){closesocket(c);return;}
 if(!SendAll(c,"CHALLENGE "+Hex(nonce)+"\n")||!ReadLine(c,line)||line.rfind("AUTH ",0)!=0){closesocket(c);return;}
 std::string proof;if(!MakeProof(expected,Hex(nonce),proof)||line.size()!=5+proof.size()){closesocket(c);return;}
 unsigned diff=0;for(size_t i=0;i<proof.size();++i)diff|=(unsigned char)proof[i]^(unsigned char)line[i+5];
 if(diff||!SendAll(c,"OK\n")){closesocket(c);return;}
 auto node=std::make_shared<WorkerSession>();node->socket=c;
 {std::lock_guard<std::mutex>lk(g_workersMutex);g_workers.push_back(node);g_connected=true;}
 Ui(L"Вычислительный узел авторизован");Log(L"Подключён новый PC2.");
 while(g_running&&node->alive){
  fd_set set;FD_ZERO(&set);FD_SET(c,&set);timeval tv{1,0};int ready=select(0,&set,nullptr,nullptr,&tv);
  if(ready==SOCKET_ERROR)break;
  if(ready==0)continue;
  if(!ReadLine(c,line))break;
  std::istringstream in(line);std::string cmd;in>>cmd;
  if(cmd=="HB"){double cpu=0,mem=0;in>>cpu>>mem;if(in){node->cpu=std::clamp(cpu,0.0,100.0);node->mem=std::clamp(mem,0.0,100.0);}continue;}
  if(cmd=="RESULT"){uint64_t value=0;in>>value;if(in){std::lock_guard<std::mutex>lk(node->resultMutex);node->result=value;node->resultReady=true;node->resultCv.notify_all();}continue;}
  if(cmd=="ERROR"){std::lock_guard<std::mutex>lk(node->resultMutex);node->resultReady=true;node->result=0;node->resultCv.notify_all();}
 }
 node->alive=false;shutdown(c,SD_BOTH);closesocket(c);node->socket=INVALID_SOCKET;
 {std::lock_guard<std::mutex>lk(g_workersMutex);g_workers.erase(std::remove(g_workers.begin(),g_workers.end(),node),g_workers.end());g_connected=!g_workers.empty();}
 {std::lock_guard<std::mutex>lk(node->resultMutex);node->resultReady=true;node->resultCv.notify_all();}
 Ui(L"Один из узлов отключился");Log(L"Вычислительный узел отключён.");
}
static void ServerLoop(){
 WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Winsock не запустился");g_running=false;return;}
 SOCKET ls=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(ls==INVALID_SOCKET){Ui(L"Не удалось создать сокет");WSACleanup();g_running=false;return;}
 g_listener=ls;BOOL yes=TRUE;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
 sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(PORT);addr.sin_addr.s_addr=htonl(INADDR_ANY);
 if(bind(ls,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR||listen(ls,32)==SOCKET_ERROR){Ui(L"Порт 47821 занят или заблокирован");closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();g_running=false;return;}
 Ui(L"PC1 запущен. Ожидаю подключения нескольких PC2.");
 while(g_running){
  fd_set set;FD_ZERO(&set);FD_SET(ls,&set);timeval tv{1,0};int ready=select(0,&set,nullptr,nullptr,&tv);
  if(ready==SOCKET_ERROR)break;if(ready==0)continue;
  SOCKET c=accept(ls,nullptr,nullptr);if(c==INVALID_SOCKET)continue;ConfigureSocket(c);
  ++g_handlerCount;std::thread([c](){WorkerSessionLoop(c);--g_handlerCount;}).detach();
 }
 shutdown(ls,SD_BOTH);closesocket(ls);g_listener=INVALID_SOCKET;
 {std::lock_guard<std::mutex>lk(g_workersMutex);for(auto&n:g_workers){n->alive=false;shutdown(n->socket,SD_BOTH);}g_connected=false;}
 while(g_handlerCount.load()>0)std::this_thread::sleep_for(std::chrono::milliseconds(50));
 {std::lock_guard<std::mutex>lk(g_workersMutex);g_workers.clear();}
 WSACleanup();g_running=false;Ui(L"Сервер остановлен");
}
static void RunDistributedTest(){
 std::vector<std::shared_ptr<WorkerSession>> nodes;
 {std::lock_guard<std::mutex>lk(g_workersMutex);nodes=g_workers;}
 nodes.erase(std::remove_if(nodes.begin(),nodes.end(),[](auto&n){return !n->alive;}),nodes.end());
 if(nodes.empty()){MessageBoxW(nullptr,L"Сначала подключите хотя бы один PC2.",L"Нет вычислительных узлов",MB_ICONWARNING);return;}
 g_taskActive=true;CpuLoad();std::this_thread::sleep_for(std::chrono::milliseconds(250));
 double localCpu=CpuLoad(),localMem=MemoryLoad();
 struct Part{std::shared_ptr<WorkerSession> node;uint64_t a,b;double weight;};
 std::vector<Part> parts;double totalWeight=std::max(0.05,(100.0-localCpu)*(100.0-localMem)/10000.0);
 for(auto&n:nodes){double freeCpu=std::max(1.0,100.0-n->cpu.load());double freeMem=std::max(1.0,100.0-n->mem.load());double weight=freeCpu*freeMem/10000.0;totalWeight+=weight;parts.push_back({n,0,0,weight});}
 const uint64_t first=2,last=TEST_END,span=last-first+1;uint64_t cursor=first;
 for(auto&p:parts){uint64_t count=(uint64_t)((double)span*p.weight/totalWeight);count=std::max<uint64_t>(1,count);p.a=cursor;p.b=std::min<uint64_t>(last,cursor+count-1);cursor=p.b+1;}
 uint64_t localA=cursor,localB=last;
 auto started=std::chrono::steady_clock::now();bool sentAny=false;
 for(auto&p:parts){
  if(p.a>p.b)continue;
  {std::lock_guard<std::mutex>lk(p.node->resultMutex);p.node->resultReady=false;p.node->result=0;}
  std::lock_guard<std::mutex>sendLock(p.node->sendMutex);
  if(p.node->alive&&SendAll(p.node->socket,"TASK PRIME "+std::to_string(p.a)+" "+std::to_string(p.b)+"\n"))sentAny=true;
 }
 uint64_t local=localA<=localB?CountPrimes(localA,localB):0,totalRemote=0;bool allOk=sentAny;
 for(auto&p:parts){
  if(p.a>p.b)continue;
  std::unique_lock<std::mutex>lk(p.node->resultMutex);
  if(!p.node->resultCv.wait_for(lk,std::chrono::seconds(45),[&]{return p.node->resultReady||!p.node->alive;})){allOk=false;continue;}
  if(!p.node->resultReady||!p.node->alive){allOk=false;continue;}totalRemote+=p.node->result;
 }
 g_taskActive=false;
 if(!allOk){Ui(L"Не все узлы вернули результат. Незавершённые части не засчитываются; повторите тест.");return;}
 auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
 std::wstringstream out;out<<L"Тест завершён: PC1="<<local<<L", удалённые узлы="<<totalRemote<<L", всего="<<(local+totalRemote)<<L", узлов="<<nodes.size()<<L", время="<<ms<<L" мс.";
 Ui(out.str());Log(out.str());
}
static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
 if(m==WM_APP_STATUS){auto*p=(std::wstring*)lp;SetWindowTextW(g_status,p->c_str());delete p;return 0;}
 if(m==WM_APP_LOG){auto*p=(std::wstring*)lp;int n=GetWindowTextLengthW(g_log);SendMessageW(g_log,EM_SETSEL,n,n);SendMessageW(g_log,EM_REPLACESEL,FALSE,(LPARAM)(*p+L"\r\n").c_str());delete p;return 0;}
 switch(m){
 case WM_CREATE:
  CreateWindowW(L"STATIC",L"PC1 — координатор нескольких вычислительных узлов",WS_CHILD|WS_VISIBLE,20,15,500,25,w,nullptr,nullptr,nullptr);
  CreateWindowW(L"STATIC",L"Общий пароль:",WS_CHILD|WS_VISIBLE,20,53,100,22,w,nullptr,nullptr,nullptr);
  g_password=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"change-this-password",WS_CHILD|WS_VISIBLE|ES_PASSWORD,125,50,220,25,w,(HMENU)10,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Запустить сервер",WS_CHILD|WS_VISIBLE,20,90,140,32,w,(HMENU)1,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Остановить",WS_CHILD|WS_VISIBLE,170,90,110,32,w,(HMENU)2,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Тест распределения",WS_CHILD|WS_VISIBLE,290,90,170,32,w,(HMENU)3,nullptr,nullptr);
  g_status=CreateWindowW(L"STATIC",L"Сервер не запущен",WS_CHILD|WS_VISIBLE,20,137,540,35,w,nullptr,nullptr,nullptr);
  g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,180,540,210,w,nullptr,nullptr,nullptr);return 0;
 case WM_COMMAND:
  if(LOWORD(wp)==1&&!g_running){wchar_t b[256]{};GetWindowTextW(g_password,b,256);if(wcslen(b)<8){MessageBoxW(w,L"Пароль должен содержать не менее 8 символов.",L"Слабый пароль",MB_ICONWARNING);return 0;}g_pass=b;g_running=true;std::thread(ServerLoop).detach();}
  if(LOWORD(wp)==2&&g_running){g_running=false;if(g_listener!=INVALID_SOCKET)shutdown(g_listener,SD_BOTH);{std::lock_guard<std::mutex>lk(g_workersMutex);for(auto&n:g_workers){n->alive=false;shutdown(n->socket,SD_BOTH);}g_connected=false;}}
  if(LOWORD(wp)==3){bool expected=false;if(g_taskActive.compare_exchange_strong(expected,true)){g_taskActive=false;std::thread(RunDistributedTest).detach();}else MessageBoxW(w,L"Задача уже выполняется.",L"Занято",MB_ICONINFORMATION);}return 0;
 case WM_DESTROY:
  g_running=false;if(g_listener!=INVALID_SOCKET)shutdown(g_listener,SD_BOTH);
  {std::lock_guard<std::mutex>lk(g_workersMutex);for(auto&n:g_workers){n->alive=false;shutdown(n->socket,SD_BOTH);}g_connected=false;}
  PostQuitMessage(0);return 0;
 }return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE,PWSTR,int show){
 WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=h;wc.lpszClassName=L"TwoPC_PC1";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
 HWND w=CreateWindowW(wc.lpszClassName,L"2-PC — PC1",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,180,140,600,450,nullptr,nullptr,h,nullptr);
 if(!w)return 1;ShowWindow(w,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}