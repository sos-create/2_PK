#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <vector>
#include <windows.h>
#include <ws2tcpip.h>
#include <dxgi.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <cstring>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <tlhelp32.h>
#include <shellapi.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dxgi.lib")
#pragma comment(lib,"d3d11.lib")
#pragma comment(lib,"shell32.lib")

static constexpr unsigned short PORT=47821;
static constexpr uint64_t TEST_END=3000000;
static constexpr UINT WM_APP_STATUS=WM_APP+1, WM_APP_LOG=WM_APP+2;
static HWND g_status{},g_log{};
static HFONT g_uiFont=nullptr;
static BOOL CALLBACK ApplyChildFont(HWND child,LPARAM font){SendMessageW(child,WM_SETFONT,(WPARAM)font,TRUE);return TRUE;}

static SOCKET g_client=INVALID_SOCKET,g_listener=INVALID_SOCKET;
static std::mutex g_sockMutex,g_readMutex;
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
 result=0;if(a<=2&&b>=2)++result;if(b<3)return true;
 static const char* shader=R"(
 StructuredBuffer<uint> BasePrimes : register(t0);
 RWByteAddressBuffer Counter : register(u0);
 cbuffer Params : register(b0) { uint StartValue; uint ItemCount; uint PrimeCount; uint Pad0; };
 [numthreads(256,1,1)]
 void main(uint3 tid : SV_DispatchThreadID) {
  uint i=tid.x;if(i>=ItemCount)return;
  uint n=StartValue+i*2;
  if(n<3||(n&1)==0)return;
  bool prime=true;
  [loop] for(uint j=0;j<PrimeCount;++j){
   uint p=BasePrimes[j];if(p>n/p)break;
   if(n%p==0){prime=false;break;}
  }
  if(prime){uint oldv;Counter.InterlockedAdd(0,1,oldv);}
 })";
 std::vector<uint32_t> basePrimes;
 uint64_t root=1;while(root+1<=b/(root+1))++root;
 std::vector<uint8_t> sieve((size_t)root+1,1);
 for(uint64_t p=3;p<=root;p+=2)if(sieve[(size_t)p]){
  basePrimes.push_back((uint32_t)p);
  if(p<=root/p)for(uint64_t q=p*p;q<=root;q+=2*p)sieve[(size_t)q]=0;
 }
 if(basePrimes.empty())basePrimes.push_back(3);
 ID3D11Device* dev=nullptr;ID3D11DeviceContext* ctx=nullptr;D3D_FEATURE_LEVEL fl{};
 const D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_1,D3D_FEATURE_LEVEL_11_0};
 HRESULT hr=D3D11CreateDevice(adapter,D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,levels,2,D3D11_SDK_VERSION,&dev,&fl,&ctx);
 if(FAILED(hr)){const D3D_FEATURE_LEVEL fallback[]={D3D_FEATURE_LEVEL_11_0};hr=D3D11CreateDevice(adapter,D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,fallback,1,D3D11_SDK_VERSION,&dev,&fl,&ctx);}
 if(FAILED(hr)||!dev||!ctx){if(ctx)ctx->Release();if(dev)dev->Release();return false;}
 ID3DBlob* bytecode=nullptr;ID3DBlob* errors=nullptr;
 hr=D3DCompile(shader,strlen(shader),"2pc_prime_gpu",nullptr,nullptr,"main","cs_5_0",D3DCOMPILE_OPTIMIZATION_LEVEL3,0,&bytecode,&errors);
 if(errors){if(FAILED(hr))OutputDebugStringA((const char*)errors->GetBufferPointer());errors->Release();}
 if(FAILED(hr)||!bytecode){if(bytecode)bytecode->Release();ctx->Release();dev->Release();return false;}
 ID3D11ComputeShader* cs=nullptr;hr=dev->CreateComputeShader(bytecode->GetBufferPointer(),bytecode->GetBufferSize(),nullptr,&cs);bytecode->Release();
 if(FAILED(hr)){ctx->Release();dev->Release();return false;}
 ID3D11Buffer* cb=nullptr;ID3D11Buffer* counter=nullptr;ID3D11Buffer* staging=nullptr;ID3D11Buffer* primeBuffer=nullptr;
 ID3D11UnorderedAccessView* uav=nullptr;ID3D11ShaderResourceView* primeView=nullptr;
 D3D11_BUFFER_DESC cbd{};cbd.ByteWidth=16;cbd.Usage=D3D11_USAGE_DEFAULT;cbd.BindFlags=D3D11_BIND_CONSTANT_BUFFER;
 hr=dev->CreateBuffer(&cbd,nullptr,&cb);
 D3D11_BUFFER_DESC bd{};bd.ByteWidth=4;bd.Usage=D3D11_USAGE_DEFAULT;bd.BindFlags=D3D11_BIND_UNORDERED_ACCESS;bd.MiscFlags=D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;
 if(SUCCEEDED(hr))hr=dev->CreateBuffer(&bd,nullptr,&counter);
 D3D11_UNORDERED_ACCESS_VIEW_DESC ud{};ud.Format=DXGI_FORMAT_R32_TYPELESS;ud.ViewDimension=D3D11_UAV_DIMENSION_BUFFER;ud.Buffer.FirstElement=0;ud.Buffer.NumElements=1;ud.Buffer.Flags=D3D11_BUFFER_UAV_FLAG_RAW;
 if(SUCCEEDED(hr))hr=dev->CreateUnorderedAccessView(counter,&ud,&uav);
 D3D11_BUFFER_DESC pd{};pd.ByteWidth=(UINT)(basePrimes.size()*sizeof(uint32_t));pd.Usage=D3D11_USAGE_IMMUTABLE;pd.BindFlags=D3D11_BIND_SHADER_RESOURCE;pd.MiscFlags=D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;pd.StructureByteStride=sizeof(uint32_t);
 D3D11_SUBRESOURCE_DATA init{};init.pSysMem=basePrimes.data();
 if(SUCCEEDED(hr))hr=dev->CreateBuffer(&pd,&init,&primeBuffer);
 D3D11_SHADER_RESOURCE_VIEW_DESC pvd{};pvd.Format=DXGI_FORMAT_UNKNOWN;pvd.ViewDimension=D3D11_SRV_DIMENSION_BUFFER;pvd.Buffer.FirstElement=0;pvd.Buffer.NumElements=(UINT)basePrimes.size();
 if(SUCCEEDED(hr))hr=dev->CreateShaderResourceView(primeBuffer,&pvd,&primeView);
 D3D11_BUFFER_DESC sd{};sd.ByteWidth=4;sd.Usage=D3D11_USAGE_STAGING;sd.CPUAccessFlags=D3D11_CPU_ACCESS_READ;
 if(SUCCEEDED(hr))hr=dev->CreateBuffer(&sd,nullptr,&staging);
 auto cleanup=[&](){if(staging)staging->Release();if(primeView)primeView->Release();if(primeBuffer)primeBuffer->Release();if(uav)uav->Release();if(counter)counter->Release();if(cb)cb->Release();if(cs)cs->Release();if(ctx)ctx->Release();if(dev)dev->Release();};
 if(FAILED(hr)){cleanup();return false;}
 uint64_t first=std::max<uint64_t>(a,3);if((first&1)==0)++first;
 constexpr uint64_t CHUNK=32768;bool success=true;
 for(uint64_t low=first;low<=b;){
  uint64_t count=std::min<uint64_t>(CHUNK,(b-low)/2+1);
  UINT params[4]={(UINT)low,(UINT)count,(UINT)basePrimes.size(),0};ctx->UpdateSubresource(cb,0,nullptr,params,0,0);
  UINT zero[4]={0,0,0,0};ctx->ClearUnorderedAccessViewUint(uav,zero);
  ctx->CSSetShader(cs,nullptr,0);ctx->CSSetConstantBuffers(0,1,&cb);ctx->CSSetShaderResources(0,1,&primeView);ctx->CSSetUnorderedAccessViews(0,1,&uav,nullptr);
  ctx->Dispatch((UINT)((count+255)/256),1,1);
  ID3D11UnorderedAccessView* nullUav=nullptr;ID3D11ShaderResourceView* nullSrv=nullptr;
  ctx->CSSetUnorderedAccessViews(0,1,&nullUav,nullptr);ctx->CSSetShaderResources(0,1,&nullSrv);
  ctx->CopyResource(staging,counter);D3D11_MAPPED_SUBRESOURCE mapped{};
  hr=ctx->Map(staging,0,D3D11_MAP_READ,0,&mapped);if(FAILED(hr)){success=false;break;}
  result+=*(const uint32_t*)mapped.pData;ctx->Unmap(staging,0);
  uint64_t next=low+count*2;if(next<=low)break;low=next;
 }
 cleanup();return success;
}
static bool CountPrimesGpu(uint64_t a,uint64_t b,uint64_t& result){
 IDXGIFactory1* f=nullptr;if(FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1),(void**)&f)))return false;
 std::vector<IDXGIAdapter1*> adapters;
 for(UINT i=0;;++i){IDXGIAdapter1* ad=nullptr;if(f->EnumAdapters1(i,&ad)==DXGI_ERROR_NOT_FOUND)break;
  DXGI_ADAPTER_DESC1 d{};bool usable=false;
  if(SUCCEEDED(ad->GetDesc1(&d))&&!(d.Flags&DXGI_ADAPTER_FLAG_SOFTWARE)){
   ID3D11Device* probe=nullptr;ID3D11DeviceContext* probeCtx=nullptr;D3D_FEATURE_LEVEL got{};
   const D3D_FEATURE_LEVEL required[]={D3D_FEATURE_LEVEL_11_0};
   usable=SUCCEEDED(D3D11CreateDevice(ad,D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,required,1,D3D11_SDK_VERSION,&probe,&got,&probeCtx));
   if(probeCtx)probeCtx->Release();if(probe)probe->Release();
  }
  if(usable)adapters.push_back(ad);else ad->Release();
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
static std::atomic<double> g_cpuRate{0.0},g_gpuRate{0.0};
static uint64_t CountPrimes(uint64_t a,uint64_t b){
 if(b<a||b<2)return 0;if(b-a<1)return CountPrimesCpu(a,b);
 uint64_t length=b-a+1;double cr=g_cpuRate.load(),gr=g_gpuRate.load();
 double gpuShare=(cr>0.0&&gr>0.0)?gr/(cr+gr):0.5;
 gpuShare=std::clamp(gpuShare,0.05,0.80);
 uint64_t gpuLength=(uint64_t)(length*gpuShare);gpuLength=std::clamp<uint64_t>(gpuLength,1,length-1);
 uint64_t split=b-gpuLength,left=0,right=0;double cpuMs=1.0,gpuMs=1.0;
 auto cpuStart=std::chrono::steady_clock::now();
 std::thread cpu([&]{left=CountPrimesCpu(a,split);cpuMs=std::max(0.1,std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-cpuStart).count());});
 auto gpuStart=std::chrono::steady_clock::now();bool gpuOk=CountPrimesGpu(split+1,b,right);
 gpuMs=std::max(0.1,std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-gpuStart).count());
 cpu.join();if(!gpuOk)return CountPrimesCpu(a,b);
 double newCpu=(double)(split-a+1)/cpuMs,newGpu=(double)gpuLength/gpuMs;
 auto smooth=[](std::atomic<double>&rate,double value){double old=rate.load();rate.store(old>0.0?old*0.65+value*0.35:value);};
 smooth(g_cpuRate,newCpu);smooth(g_gpuRate,newGpu);
 return left+right;
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
static bool EnsureFirewallRules(){
 const wchar_t* args=L"/c netsh advfirewall firewall add rule name=\"2-PC PC1 TCP 47821\" dir=in action=allow protocol=TCP localport=47821 profile=any & netsh advfirewall firewall add rule name=\"2-PC PC1 UDP 47820\" dir=in action=allow protocol=UDP localport=47820 profile=any";
 SHELLEXECUTEINFOW se{};se.cbSize=sizeof(se);se.fMask=SEE_MASK_NOCLOSEPROCESS;se.lpVerb=L"runas";se.lpFile=L"cmd.exe";se.lpParameters=args;se.nShow=SW_HIDE;
 if(!ShellExecuteExW(&se))return false;
 if(se.hProcess){WaitForSingleObject(se.hProcess,20000);DWORD code=1;GetExitCodeProcess(se.hProcess,&code);CloseHandle(se.hProcess);return code==0;}
 return false;
}
static void ServerLoop(){
 WSADATA wd{};if(WSAStartup(MAKEWORD(2,2),&wd)!=0){Ui(L"Winsock не запустился");g_running=false;return;}
 SOCKET ls=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(ls==INVALID_SOCKET){Ui(L"Не удалось создать сокет");WSACleanup();g_running=false;return;}
 g_listener=ls;BOOL yes=TRUE;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
 sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(PORT);addr.sin_addr.s_addr=htonl(INADDR_ANY);
 if(bind(ls,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR||listen(ls,1)==SOCKET_ERROR){Ui(L"Порт 47821 занят или заблокирован");closesocket(ls);g_listener=INVALID_SOCKET;WSACleanup();g_running=false;return;}
 if(!EnsureFirewallRules())Log(L"Не удалось автоматически добавить правила брандмауэра. Разрешите запрос UAC или вручную разрешите TCP 47821 и UDP 47820 для PC1.");
 Ui(L"Сервер запущен. Ожидаю PC2; автообнаружение по Ethernet включено.");
 std::thread discovery(DiscoveryLoop);
 while(g_running){
  SOCKET c=accept(ls,nullptr,nullptr);if(c==INVALID_SOCKET){if(!g_running)break;continue;}ConfigureSocket(c);
  std::string line;
  {std::lock_guard<std::mutex>lk(g_sockMutex);g_client=c;}
  g_connected=true;Ui(L"PC2 подключён напрямую по Ethernet");Log(L"PC2 подключён без парольной авторизации.");
  while(g_running&&g_connected){
   {
    std::lock_guard<std::mutex> readLock(g_readMutex);
    if(g_taskActive){std::this_thread::sleep_for(std::chrono::milliseconds(50));continue;}
    fd_set set;FD_ZERO(&set);FD_SET(c,&set);timeval tv{1,0};int ready=select(0,&set,nullptr,nullptr,&tv);
    if(ready==SOCKET_ERROR)break;
    if(ready>0){if(!ReadLine(c,line))break;std::istringstream in(line);std::string cmd;double cpu=0,mem=0;in>>cmd>>cpu>>mem;if(cmd=="HB"&&in){unsigned threads=0,gpus=0;uint64_t ram=0,vram=0,shared=0;in>>threads>>ram>>gpus>>vram>>shared;unsigned computeGpus=0;in>>computeGpus;g_remoteComputeGpuCount=computeGpus;g_remoteCpu=std::clamp(cpu,0.0,100.0);g_remoteMem=std::clamp(mem,0.0,100.0);g_remoteThreads=threads;g_remoteRamMB=ram;g_remoteGpuCount=gpus;g_remoteVramMB=vram;g_remoteSharedGpuMB=shared;}}
   }
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
 double localFree=std::max(0.02,1.0-localCpu/100.0)*std::max(0.05,1.0-localMem/100.0)*std::max(1u,CpuThreads());
 double remoteFree=std::max(0.02,1.0-remoteCpu/100.0)*std::max(0.05,1.0-remoteMem/100.0)*std::max(1u,g_remoteThreads.load());
 double remoteShare=remoteFree/(localFree+remoteFree);
 if(remoteCpu>92.0||remoteMem>94.0)remoteShare=0.0;
 remoteShare=std::clamp(remoteShare,0.0,0.95);
 if(remoteShare<=0.001){
  auto t0=std::chrono::steady_clock::now();uint64_t localOnly=CountPrimes(2,TEST_END);
  auto dt=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
  std::wstringstream msg;msg<<L"PC2 перегружен; задача выполнена локально: "<<localOnly<<L", время="<<dt<<L" мс.";
  Ui(msg.str());Log(msg.str());return;
 }
 uint64_t startN=2,span=TEST_END-startN+1;
 uint64_t remoteCount=(uint64_t)(span*remoteShare);
 uint64_t split=TEST_END-remoteCount;
 if(split<startN)split=startN;
 g_taskActive=true;Ui(L"Распределяю тестовую задачу между CPU и совместимыми GPU двух компьютеров...");
 auto started=std::chrono::steady_clock::now();
 if(!SendAll(s,"TASK PRIME "+std::to_string(split+1)+" "+std::to_string(TEST_END)+"\n")){g_taskActive=false;Ui(L"Не удалось отправить задачу PC2");return;}
 uint64_t local=CountPrimes(startN,split);
 std::string answer;bool received=false;
 while(g_running&&g_connected){std::lock_guard<std::mutex> readLock(g_readMutex);if(!ReadLine(s,answer))break;if(answer.rfind("HB ",0)==0){std::istringstream hb(answer);std::string tag;double cpu,mem;hb>>tag>>cpu>>mem;if(hb){unsigned threads=0,gpus=0;uint64_t ram=0,vram=0,shared=0;hb>>threads>>ram>>gpus>>vram>>shared;unsigned computeGpus=0;hb>>computeGpus;g_remoteComputeGpuCount=computeGpus;g_remoteCpu=std::clamp(cpu,0.0,100.0);g_remoteMem=std::clamp(mem,0.0,100.0);g_remoteThreads=threads;g_remoteRamMB=ram;g_remoteGpuCount=gpus;g_remoteVramMB=vram;g_remoteSharedGpuMB=shared;}continue;}received=true;break;}
 g_taskActive=false;
 if(!received||answer.rfind("RESULT ",0)!=0){Ui(L"PC2 не вернул результат. Проверьте соединение.");return;}
 uint64_t remote=0;try{remote=std::stoull(answer.substr(7));}catch(...){Ui(L"Некорректный ответ PC2");return;}
 auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
 auto localGpu=GetGpuInventory();std::wstringstream out;out<<((local+remote)==216816?L"ПРОВЕРКА ПРОЙДЕНА: ":L"ОШИБКА ПРОВЕРКИ: ")<<L"Тест завершён: PC1="<<local<<L", PC2="<<remote<<L", всего="<<(local+remote)<<L". Доля PC2="<<(int)(remoteShare*100)<<L"%, CPU PC1="<<(int)localCpu<<L"%/"<<CpuThreads()<<L" потоков, PC2="<<(int)remoteCpu<<L"%/"<<g_remoteThreads.load()<<L" потоков, RAM доступно PC1="<<AvailableRamMB()<<L" МБ, PC2="<<g_remoteRamMB.load()<<L" МБ, GPU PC1="<<localGpu.count<<L" ("<<localGpu.dedicatedMB<<L" МБ VRAM), PC2="<<g_remoteGpuCount.load()<<L" ("<<g_remoteVramMB.load()<<L" МБ VRAM, D3D11 compute="<<g_remoteComputeGpuCount.load()<<L"), время="<<ms<<L" мс.";
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
  CreateWindowW(L"BUTTON",L"Проверить распределение",WS_CHILD|WS_VISIBLE,290,55,170,32,w,(HMENU)3,nullptr,nullptr);
  g_status=CreateWindowW(L"STATIC",L"Сервер не запущен",WS_CHILD|WS_VISIBLE,20,102,540,35,w,nullptr,nullptr,nullptr);
  g_log=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,20,145,540,245,w,nullptr,nullptr,nullptr);g_uiFont=CreateFontW(-16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");if(g_uiFont)EnumChildWindows(w,ApplyChildFont,(LPARAM)g_uiFont);return 0;
 case WM_COMMAND:
  if(LOWORD(wp)==1&&!g_running){g_running=true;std::thread(ServerLoop).detach();}
  if(LOWORD(wp)==2&&g_running){g_running=false;if(g_listener!=INVALID_SOCKET){shutdown(g_listener,SD_BOTH);closesocket(g_listener);}std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client!=INVALID_SOCKET){shutdown(g_client,SD_BOTH);closesocket(g_client);g_client=INVALID_SOCKET;}g_connected=false;}
  if(LOWORD(wp)==3)std::thread(RunDistributedTest).detach();return 0;
 case WM_DESTROY:
  if(g_uiFont){DeleteObject(g_uiFont);g_uiFont=nullptr;}
  g_running=false;if(g_listener!=INVALID_SOCKET){shutdown(g_listener,SD_BOTH);closesocket(g_listener);}
  {std::lock_guard<std::mutex>lk(g_sockMutex);if(g_client!=INVALID_SOCKET){shutdown(g_client,SD_BOTH);closesocket(g_client);g_client=INVALID_SOCKET;}}
  PostQuitMessage(0);return 0;
 }return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE h,HINSTANCE,PWSTR,int show){
 WNDCLASSW wc{};wc.lpfnWndProc=WndProc;wc.hInstance=h;wc.lpszClassName=L"TwoPC_PC1";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
 HWND w=CreateWindowW(wc.lpszClassName,L"2-PC — PC1 (русский интерфейс)",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,180,140,600,450,nullptr,nullptr,h,nullptr);
 if(!w)return 1;ShowWindow(w,show);MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return 0;
}