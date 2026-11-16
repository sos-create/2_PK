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
static SOCKET g_client=INVALID_SOCKET,g_listener=INVALID_SOCKET;
static std::mutex g_sockMutex;
static std::atomic<bool> g_running{false},g_connected{false},g_taskActive{false};
static std::atomic<double> g_remoteCpu{45.0},g_remoteMem{0.0};
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
static void ServerLoop(){
 WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Winsock не запустился");g_running=false;return;}
 SOCKET ls=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(ls==INVALID_SOCKET){Ui(L"Не удалось создать сокет");WSACleanup();g_running=false;return;}
 g_listener=ls;BOOL yes=TRUE;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
 sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(PORT);addr.sin_addr.s_addr=htonl(INADDR_ANY);
 if(bind(ls,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR||listen(ls,1)==SOCKET_ERROR){Ui(L"Порт 47821 занят или заблокирован");closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();g_running=false;return;}
 Ui(L"Сервер запущен. Ожидаю PC2 на порту 47821.");
 while(g_running){
  SOCKET c=accept(ls,nullptr,nullptr);if(c==INVALID_SOCKET){if(!g_running)break;continue;}ConfigureSocket(c);
  std::string expected,line;int n=WideCharToMultiByte(CP_UTF8,0,g_pass.c_str(),-1,nullptr,0,nullptr,nullptr);
  if(n>1){expected.resize(n);WideCharToMultiByte(CP_UTF8,0,g_pass.c_str(),-1,expected.data(),n,nullptr,nullptr);expected.resize(n-1);}
  std::vector<UCHAR> nonce(32);if(BCryptGenRandom(nullptr,nonce.data(),(ULONG)nonce.size(),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0){closesocket(c);continue;}
  if(!SendAll(c,"CHALLENGE "+Hex(nonce)+"\n")||!ReadLine(c,line)||line.rfind("AUTH ",0)!=0){closesocket(c);continue;}
  std::string proof;if(!MakeProof(expected,Hex(nonce),proof)||line.size()!=5+proof.size()){closesocket(c);continue;}
  unsigned diff=0;for(size_t i=0;i<proof.size();++i)diff|=(unsigned char)proof[i]^(unsigned char)line[i+5];
  if(diff!=0||!SendAll(c,"OK\n")){closesocket(c);continue;}
  {std::lock_guard<std::mutex>lk(g_sockMutex);g_client=c;}
  g_connected=true;Ui(L"PC2 подключён и авторизован");Log(L"PC2 подключён.");
  while(g_running&&g_connected){
   if(g_taskActive){std::this_thread::sleep_for(std::chrono::milliseconds(100));continue;}
   fd_set set;FD_ZERO(&set);FD_SET(c,&set);timeval tv{1,0};int ready=select(0,&set,nullptr,nullptr,&tv);
   if(ready==SOCKET_ERROR)break;
   if(ready>0){if(!ReadLine(c,line))break;std::istringstream in(line);std::string cmd;double cpu,mem;in>>cmd>>cpu>>mem;if(cmd=="HB"&&in){g_remoteCpu=std::clamp(cpu,0.0,100.0);g_remoteMem=std::clamp(mem,0.0,100.0);}}
  }
  {std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client==c)g_client=INVALID_SOCKET;}
  closesocket(c);g_connected=false;Ui(L"PC2 отключён. Ожидаю повторное подключение.");Log(L"Соединение с PC2 закрыто.");
 }
 if(ls!=INVALID_SOCKET)closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();g_running=false;Ui(L"Сервер остановлен");
}
static void RunDistributedTest(){
 SOCKET s;{std::lock_guard<std::mutex>lk(g_sockMutex);s=g_client;}
 if(!g_connected||s==INVALID_SOCKET){MessageBoxW(nullptr,L"Сначала подключите PC2.",L"Нет вычислительного узла",MB_ICONWARNING);return;}
 CpuLoad();std::this_thread::sleep_for(std::chrono::milliseconds(250));double localCpu=CpuLoad();double remoteCpu=g_remoteCpu.load();
 double localMem=MemoryLoad(),remoteMem=g_remoteMem.load();
 double localFree=std::max(3.0,100.0-localCpu)*std::max(5.0,100.0-localMem)/100.0;
 double remoteFree=std::max(3.0,100.0-remoteCpu)*std::max(5.0,100.0-remoteMem)/100.0;
 double remoteShare=remoteFree/(localFree+remoteFree);
 if(remoteCpu>90.0||remoteMem>92.0)remoteShare=0.10;
 if(localCpu>92.0&&remoteCpu<80.0&&remoteMem<85.0)remoteShare=0.80;
 remoteShare=std::clamp(remoteShare,0.15,0.80);
 uint64_t startN=2,span=TEST_END-startN+1;
 uint64_t remoteCount=(uint64_t)(span*remoteShare);
 uint64_t split=TEST_END-remoteCount;
 if(split<startN)split=startN;
 g_taskActive=true;Ui(L"Распределяю задачу по текущей загрузке CPU...");
 auto started=std::chrono::steady_clock::now();
 if(!SendAll(s,"TASK PRIME "+std::to_string(split+1)+" "+std::to_string(TEST_END)+"\n")){g_taskActive=false;Ui(L"Не удалось отправить задачу PC2");return;}
 uint64_t local=CountPrimes(startN,split);
 std::string answer;bool received=false;
 while(g_running&&g_connected){if(!ReadLine(s,answer))break;if(answer.rfind("HB ",0)==0){std::istringstream hb(answer);std::string tag;double cpu,mem;hb>>tag>>cpu>>mem;if(hb){g_remoteCpu=std::clamp(cpu,0.0,100.0);g_remoteMem=std::clamp(mem,0.0,100.0);}continue;}received=true;break;}
 g_taskActive=false;
 if(!received||answer.rfind("RESULT ",0)!=0){Ui(L"PC2 не вернул результат. Проверьте соединение.");return;}
 uint64_t remote=0;try{remote=std::stoull(answer.substr(7));}catch(...){Ui(L"Некорректный ответ PC2");return;}
 auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
 std::wstringstream out;out<<L"Тест завершён: PC1="<<local<<L", PC2="<<remote<<L", всего="<<(local+remote)<<L". Доля PC2="<<(int)(remoteShare*100)<<L"%, CPU PC1="<<(int)localCpu<<L"%, PC2="<<(int)remoteCpu<<L"%, RAM PC1="<<(int)localMem<<L"%, RAM PC2="<<(int)remoteMem<<L"%, время="<<ms<<L" мс.";
 Ui(out.str());Log(out.str());
}
static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
 if(m==WM_APP_STATUS){auto*p=(std::wstring*)lp;SetWindowTextW(g_status,p->c_str());delete p;return 0;}
 if(m==WM_APP_LOG){auto*p=(std::wstring*)lp;int n=GetWindowTextLengthW(g_log);SendMessageW(g_log,EM_SETSEL,n,n);SendMessageW(g_log,EM_REPLACESEL,FALSE,(LPARAM)(*p+L"\r\n").c_str());delete p;return 0;}
 switch(m){
 case WM_CREATE:
  CreateWindowW(L"STATIC",L"PC1 — координатор и адаптивный планировщик",WS_CHILD|WS_VISIBLE,20,15,500,25,w,nullptr,nullptr,nullptr);
  CreateWindowW(L"STATIC",L"Общий пароль:",WS_CHILD|WS_VISIBLE,20,53,100,22,w,nullptr,nullptr,nullptr);
  g_password=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"change-this-password",WS_CHILD|WS_VISIBLE|ES_PASSWORD,125,50,220,25,w,(HMENU)10,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Запустить сервер",WS_CHILD|WS_VISIBLE,20,90,140,32,w,(HMENU)1,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Остановить",WS_CHILD|WS_VISIBLE,170,90,110,32,w,(HMENU)2,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Тест распределения",WS_CHILD|WS_VISIBLE,290,90,170,32,w,(HMENU)3,nullptr,nullptr);
  g_status=CreateWindowW(L"STATIC",L"Сервер не запущен",WS_CHILD|WS_VISIBLE,20,137,540,35,w,nullptr,nullptr,nullptr);
  g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,180,540,210,w,nullptr,nullptr,nullptr);return 0;
 case WM_COMMAND:
  if(LOWORD(wp)==1&&!g_running){wchar_t b[256]{};GetWindowTextW(g_password,b,256);if(wcslen(b)<8){MessageBoxW(w,L"Пароль должен содержать не менее 8 символов.",L"Слабый пароль",MB_ICONWARNING);return 0;}g_pass=b;g_running=true;std::thread(ServerLoop).detach();}
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