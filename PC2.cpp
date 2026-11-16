#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <vector>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <dxgi.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <cstring>
#include <algorithm>
#include <string>
#include <thread>
#include <atomic>
#include <sstream>
#include <chrono>
#include <cstdint>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"dxgi.lib")
#pragma comment(lib,"d3d11.lib")

static constexpr UINT WM_APP_STATUS=WM_APP+1,WM_APP_LOG=WM_APP+2;
static HWND g_ip{},g_status{},g_log{};
static SOCKET g_socket=INVALID_SOCKET;
static std::atomic<bool> g_connected{false},g_stop{false};
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
   ++out.count;out.dedicatedMB+=d.DedicatedVideoMemory/(1024ull*1024ull);out.sharedMB+=d.SharedSystemMemory/(1024ull*1024ull);
   ID3D11Device* dev=nullptr;ID3D11DeviceContext* ctx=nullptr;D3D_FEATURE_LEVEL obtained{};const D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_1,D3D_FEATURE_LEVEL_10_0};
   if(SUCCEEDED(D3D11CreateDevice(a,D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,(UINT)_countof(levels),D3D11_SDK_VERSION,&dev,&obtained,&ctx))){if(obtained>=D3D_FEATURE_LEVEL_11_0)++out.computeCount;if(ctx)ctx->Release();if(dev)dev->Release();}
  }a->Release();
 }f->Release();return out;
}
static std::string MakeHeartbeat(){
 static const GpuInventory g=GetGpuInventory();std::ostringstream hb;hb<<"HB "<<CpuLoad()<<" "<<MemoryLoad()<<" "<<CpuThreads()<<" "<<AvailableRamMB()<<" "<<g.count<<" "<<g.dedicatedMB<<" "<<g.sharedMB<<" "<<g.computeCount<<"\n";return hb.str();
}
static uint64_t CountPrimesCpuSingle(uint64_t a,uint64_t b){
 if(b<a||b<2)return 0;a=std::max<uint64_t>(a,2);
 uint64_t root=1;while(root+1<=b/(root+1))++root;
 std::vector<uint8_t> baseMark((size_t)root+1,1);std::vector<uint32_t> primes;
 for(uint64_t p=2;p<=root;++p)if(baseMark[(size_t)p]){
  primes.push_back((uint32_t)p);
  if(p<=root/p)for(uint64_t q=p*p;q<=root;q+=p)baseMark[(size_t)q]=0;
 }
 constexpr uint64_t BLOCK=1u<<18;uint64_t total=0;
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
static uint64_t CountPrimesCpu(uint64_t a,uint64_t b){
 if(b<a||b<2)return 0;
 unsigned threads=std::max(1u,std::min( CpuThreads(), (unsigned)std::max<uint64_t>(1,(b-a+1)/(1u<<18))));
 if(threads<=1)return CountPrimesCpuSingle(a,b);
 std::vector<std::thread> pool;std::vector<uint64_t> sums(threads,0);
 uint64_t length=b-a+1,chunk=(length+threads-1)/threads;
 for(unsigned i=0;i<threads;++i){
  uint64_t lo=a+(uint64_t)i*chunk;if(lo>b)break;
  uint64_t hi=std::min<uint64_t>(b,lo+chunk-1);
  pool.emplace_back([&,i,lo,hi]{sums[i]=CountPrimesCpuSingle(lo,hi);});
 }
 for(auto&t:pool)t.join();uint64_t total=0;for(auto v:sums)total+=v;return total;
}
static bool CountPrimesGpuOnAdapter(IDXGIAdapter1* adapter,uint64_t a,uint64_t b,uint64_t& result){
 if(b<a)return false;
 static const char* shader=R"(
 RWByteAddressBuffer Counter : register(u0);
 cbuffer Params : register(b0) { uint StartValue; uint ItemCount; uint Pad0; uint Pad1; };
 [numthreads(256,1,1)]
 void main(uint3 tid : SV_DispatchThreadID) {
  uint i=tid.x;if(i>=ItemCount)return;
  uint n=StartValue+i*2;
  if(n==2){uint oldv;Counter.InterlockedAdd(0,1,oldv);return;}
  if(n<2||(n&1)==0)return;
  bool prime=true;
  [loop] for(uint d=3;d<=n/d;d+=2){if(n%d==0){prime=false;break;}}
  if(prime){uint oldv;Counter.InterlockedAdd(0,1,oldv);}
 })";
 ID3D11Device* dev=nullptr;ID3D11DeviceContext* ctx=nullptr;D3D_FEATURE_LEVEL fl{};
 const D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_1,D3D_FEATURE_LEVEL_11_0};
 HRESULT hr=D3D11CreateDevice(adapter,D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,2,D3D11_SDK_VERSION,&dev,&fl,&ctx);
 if(FAILED(hr)){const D3D_FEATURE_LEVEL fallback[]={D3D_FEATURE_LEVEL_11_0};hr=D3D11CreateDevice(adapter,D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,fallback,1,D3D11_SDK_VERSION,&dev,&fl,&ctx);}
 if(FAILED(hr)||!dev||!ctx){if(ctx)ctx->Release();if(dev)dev->Release();return false;}
 ID3DBlob* bytecode=nullptr;ID3DBlob* errors=nullptr;
 hr=D3DCompile(shader,strlen(shader),"2pc_prime_gpu",nullptr,nullptr,"main","cs_5_0",D3DCOMPILE_OPTIMIZATION_LEVEL3,0,&bytecode,&errors);
 if(errors)errors->Release();if(FAILED(hr)||!bytecode){if(bytecode)bytecode->Release();ctx->Release();dev->Release();return false;}
 ID3D11ComputeShader* cs=nullptr;hr=dev->CreateComputeShader(bytecode->GetBufferPointer(),bytecode->GetBufferSize(),nullptr,&cs);bytecode->Release();
 if(FAILED(hr)){ctx->Release();dev->Release();return false;}
 D3D11_BUFFER_DESC cbd{};cbd.ByteWidth=16;cbd.Usage=D3D11_USAGE_DEFAULT;cbd.BindFlags=D3D11_BIND_CONSTANT_BUFFER;
 ID3D11Buffer* cb=nullptr;hr=dev->CreateBuffer(&cbd,nullptr,&cb);
 D3D11_BUFFER_DESC bd{};bd.ByteWidth=4;bd.Usage=D3D11_USAGE_DEFAULT;bd.BindFlags=D3D11_BIND_UNORDERED_ACCESS;bd.MiscFlags=D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;
 ID3D11Buffer* counter=nullptr;if(SUCCEEDED(hr))hr=dev->CreateBuffer(&bd,nullptr,&counter);
 D3D11_UNORDERED_ACCESS_VIEW_DESC ud{};ud.Format=DXGI_FORMAT_R32_TYPELESS;ud.ViewDimension=D3D11_UAV_DIMENSION_BUFFER;ud.Buffer.FirstElement=0;ud.Buffer.NumElements=1;ud.Buffer.Flags=D3D11_BUFFER_UAV_FLAG_RAW;
 ID3D11UnorderedAccessView* uav=nullptr;if(SUCCEEDED(hr))hr=dev->CreateUnorderedAccessView(counter,&ud,&uav);
 D3D11_BUFFER_DESC sd{};sd.ByteWidth=4;sd.Usage=D3D11_USAGE_STAGING;sd.CPUAccessFlags=D3D11_CPU_ACCESS_READ;
 ID3D11Buffer* staging=nullptr;if(SUCCEEDED(hr))hr=dev->CreateBuffer(&sd,nullptr,&staging);
 if(FAILED(hr)){if(staging)staging->Release();if(uav)uav->Release();if(counter)counter->Release();if(cb)cb->Release();cs->Release();ctx->Release();dev->Release();return false;}
 result=0;uint64_t first=a;if(first<3)first=3;if((first&1)==0)++first;
 constexpr uint64_t CHUNK=32768;
 if(a<=2&&b>=2)++result;
 for(uint64_t low=first;low<=b;){
  uint64_t count=std::min<uint64_t>(CHUNK,(b-low)/2+1);
  UINT params[4]={(UINT)low,(UINT)count,0,0};ctx->UpdateSubresource(cb,0,nullptr,params,0,0);
  UINT zero[4]={0,0,0,0};ctx->ClearUnorderedAccessViewUint(uav,zero);
  ctx->CSSetShader(cs,nullptr,0);ctx->CSSetConstantBuffers(0,1,&cb);ctx->CSSetUnorderedAccessViews(0,1,&uav,nullptr);
  ctx->Dispatch((UINT)((count+255)/256),1,1);
  ID3D11UnorderedAccessView* nullUav=nullptr;ctx->CSSetUnorderedAccessViews(0,1,&nullUav,nullptr);
  ctx->CopyResource(staging,counter);D3D11_MAPPED_SUBRESOURCE mapped{};
  hr=ctx->Map(staging,0,D3D11_MAP_READ,0,&mapped);if(FAILED(hr))break;
  result+=*(const uint32_t*)mapped.pData;ctx->Unmap(staging,0);
  uint64_t next=low+count*2;if(next<=low)break;low=next;
 }
 staging->Release();uav->Release();counter->Release();cb->Release();cs->Release();ctx->Release();dev->Release();
 return SUCCEEDED(hr);
}
static bool CountPrimesGpu(uint64_t a,uint64_t b,uint64_t& result){
 IDXGIFactory1* f=nullptr;if(FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1),(void**)&f)))return false;
 std::vector<IDXGIAdapter1*> adapters;
 for(UINT i=0;;++i){IDXGIAdapter1* ad=nullptr;if(f->EnumAdapters1(i,&ad)==DXGI_ERROR_NOT_FOUND)break;
  DXGI_ADAPTER_DESC1 d{};if(SUCCEEDED(ad->GetDesc1(&d))&&!(d.Flags&DXGI_ADAPTER_FLAG_SOFTWARE))adapters.push_back(ad);else ad->Release();
 }
 f->Release();if(adapters.empty())return false;
 std::vector<uint64_t> sums(adapters.size(),0);std::vector<int> ok(adapters.size(),0);std::vector<std::thread> jobs;
 uint64_t length=b>=a?b-a+1:0,chunk=(length+adapters.size()-1)/adapters.size();
 for(size_t i=0;i<adapters.size();++i){
  uint64_t lo=a+(uint64_t)i*chunk;if(lo>b){adapters[i]->Release();continue;}
  uint64_t hi=std::min<uint64_t>(b,lo+chunk-1);
  jobs.emplace_back([&,i,lo,hi]{ok[i]=CountPrimesGpuOnAdapter(adapters[i],lo,hi,sums[i]);});
 }
 for(auto&t:jobs)t.join();result=0;bool all=true;
 for(size_t i=0;i<adapters.size();++i){result+=sums[i];if(!ok[i])all=false;adapters[i]->Release();}
 return all;
}
static uint64_t CountPrimes(uint64_t a,uint64_t b){
 if(b<a||b<2)return 0;
 if(a<=2&&b>=2){if(a==2&&b==2)return 1;uint64_t mid=a+(b-a)/2; if(mid<2)mid=2;
  uint64_t left=0,right=0;std::thread cpu([&]{left=CountPrimesCpu(a,mid);});
  bool gpuOk=CountPrimesGpu(mid+1,b,right);cpu.join();
  if(gpuOk)return left+right;
  return CountPrimesCpu(a,b);
 }
 uint64_t mid=a+(b-a)/2,left=0,right=0;
 std::thread cpu([&]{left=CountPrimesCpu(a,mid);});
 bool gpuOk=CountPrimesGpu(mid+1,b,right);cpu.join();
 return gpuOk?left+right:CountPrimesCpu(a,b);
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
  if(ad->OperStatus!=IfOperStatusUp||ad->IfType!=IF_TYPE_ETHERNET_CSMACD)continue;
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
 if(g_connected)return;wchar_t host[256]{};GetWindowTextW(g_ip,host,256);
 WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Ошибка Winsock");return;}
 if(!host[0]||_wcsicmp(host,L"AUTO")==0){std::string found;Ui(L"Автоматически ищу PC1 по Ethernet...");
  if(!DiscoverPC1(found)){WSACleanup();Ui(L"PC1 не найден. Проверьте кабель и запущенный сервер.");return;}
  MultiByteToWideChar(CP_UTF8,0,found.c_str(),-1,host,256);SetWindowTextW(g_ip,host);
 }
 char h[256]{};WideCharToMultiByte(CP_UTF8,0,host,-1,h,256,nullptr,nullptr);
 addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;hints.ai_protocol=IPPROTO_TCP;addrinfo*res=nullptr;
 if(getaddrinfo(h,"47821",&hints,&res)!=0){Ui(L"Неверный IP");WSACleanup();return;}
 SOCKET s=INVALID_SOCKET;for(auto*q=res;q;q=q->ai_next){s=socket(q->ai_family,q->ai_socktype,q->ai_protocol);if(s!=INVALID_SOCKET&&connect(s,q->ai_addr,(int)q->ai_addrlen)==0)break;if(s!=INVALID_SOCKET)closesocket(s);s=INVALID_SOCKET;}freeaddrinfo(res);
 if(s==INVALID_SOCKET){Ui(L"Не удалось подключиться. Проверьте IP и брандмауэр.");WSACleanup();return;}ConfigureSocket(s);
 g_socket=s;g_stop=false;g_connected=true;Ui(L"Подключено напрямую по Ethernet без пароля.");Log(L"Прямое Ethernet-соединение установлено.");std::thread(Worker,s).detach();
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
  CreateWindowW(L"BUTTON",L"Подключиться",WS_CHILD|WS_VISIBLE,20,88,140,32,w,(HMENU)1,nullptr,nullptr);
  CreateWindowW(L"BUTTON",L"Отключиться",WS_CHILD|WS_VISIBLE,170,88,140,32,w,(HMENU)2,nullptr,nullptr);
  g_status=CreateWindowW(L"STATIC",L"Не подключено",WS_CHILD|WS_VISIBLE,20,133,540,35,w,nullptr,nullptr,nullptr);
  g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,175,540,215,w,nullptr,nullptr,nullptr);return 0;
 case WM_COMMAND:if(LOWORD(wp)==1)std::thread(Connect).detach();if(LOWORD(wp)==2)Disconnect();return 0;
 case WM_DESTROY:Disconnect();PostQuitMessage(0);return 0;
 }return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE,PWSTR,int show){
 WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=h;wc.lpszClassName=L"TwoPC_PC2";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
 HWND w=CreateWindowW(wc.lpszClassName,L"2-PC — PC2",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,200,160,600,450,nullptr,nullptr,h,nullptr);
 if(!w)return 1;ShowWindow(w,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}