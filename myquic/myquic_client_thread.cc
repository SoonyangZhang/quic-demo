#include <iostream>
#include "net/third_party/quiche/src/quic/myquic/myquic_client_thread.h"
#include "net/third_party/quiche/src/quic/core/quic_epoll_alarm_factory.h"
#include "net/quic/platform/impl/quic_epoll_clock.h"
namespace quic{
std::unique_ptr<MyQuicClient> MyQuicClientFactory::CreateClient(
    QuicSession::Visitor *owner,
    std::string host_for_lookup,
    uint16_t port,
    ParsedQuicVersionVector versions,
    std::unique_ptr<ProofVerifier> verifier) {
  QuicSocketAddress addr =
      tools::LookupAddress(host_for_lookup, quiche::QuicheStrCat(port));
  if (!addr.IsInitialized()) {
    QUIC_LOG(ERROR) << "Unable to resolve address: " << host_for_lookup;
    return nullptr;
  }
  QuicServerId server_id(host_for_lookup, port, false);
  return std::make_unique<MyQuicClient>(owner,addr, server_id, versions, 
                                        context_,backend_,std::move(verifier));
}
ClientThread::RequestClientConfig::RequestClientConfig(const char*indication,size_t size,
                    uint8_t request,QuicIpAddress ip):id(request){
    local=ip;      
    length=std::min(size,kMaxJoinIndicationSize);
    if(length>0){
        memcpy(join_indication,indication,length); 
    }
}
ClientThread::ClientThread(MyQuicBackend *backend)
:QuicThread("MyQuicClientThread"){
    backend_=backend;
    epoll_server_.reset(new QuicEpollServer());
    alarm_factory_.reset(new QuicEpollAlarmFactory(epoll_server_.get()));
    clock_.reset(new QuicEpollClock(epoll_server_.get()));
    factory_.reset(new MyQuicClientFactory(this,backend_));
}
ClientThread::~ClientThread(){
    std::cout<<"active "<<active_clients_.size()<<std::endl;
    std::cout<<"inactive "<<inactive_clients_.size()<<std::endl;
}
void ClientThread::Run(){
    if(context_id_==base::kInvalidThreadId){
        context_id_=base::PlatformThread::CurrentId();
    }
    while(!quit_.HasBeenNotified()){
        HandleInactiveClient();
        std::deque <RequestClientConfig> requests;
        {
            QuicWriterMutexLock lock(&request_mutex_);
            requests.swap(requests_);
        }      
       if(requests.size()>0){        
            while(!requests.empty()){
                auto it=requests.begin();
                uint8_t id=(*it).id;
                QuicIpAddress local=(*it).local;
                size_t length=(*it).length;
                const char *data=(*it).join_indication;
                requests.erase(it);
                MyQuicToyClient *client=new MyQuicToyClient(factory_.get());
                client->set_notifier(this);
                client->set_bind_to_address(local);
                std::string indication(data,length);
                if(length>0){                                    
                    client->JoinIndication(indication);}                
                int ret=client->InitialAndConnect();
                if(ret!=0){
                    delete client;
                    backend_->NotifyFailure(indication,id);
                }else{
                    active_clients_.insert(client);
                }
        }
        }
        std::deque<std::unique_ptr<QueuedTask>> tasks;
        {
            QuicWriterMutexLock lock(&task_mutex_);
            tasks.swap(queued_tasks_);
        }
        while(!tasks.empty()){
            tasks.front()->Run();
            tasks.pop_front();
        }         
        epoll_server_->WaitForEventsAndExecuteCallbacks();        
    }
    ExitGracefully();
    HandleInactiveClient();
}
void ClientThread::Quit(){
    if (!quit_.HasBeenNotified()) {
        quit_.Notify();
    }
    Join();
}
void ClientThread::RequestClient(std::string &indication,int id,QuicIpAddress local){
    QuicWriterMutexLock lock(&request_mutex_);
    requests_.emplace_back(indication.data(),indication.size(),(uint8_t)id,local);
}
void ClientThread::OnConnectionClosed(MyQuicToyClient *client,
                        quic::QuicErrorCode error,
                      const std::string& error_details){
    auto it=active_clients_.find(client);
    std::cout<<"close client"<<std::endl;
    if(it==active_clients_.end()){
        std::cout<<"why client not find"<<std::endl;
    }else{
        active_clients_.erase(it);
    }
    inactive_clients_.insert(client);
}

QuicClock *ClientThread::clock(){
    return clock_.get();
} 
QuicAlarmFactory* ClientThread::alarm_factory(){
    return alarm_factory_.get();
}
QuicEpollServer* ClientThread::epoll_server(){
    return epoll_server_.get();
}
void ClientThread::PostInnerTask(std::unique_ptr<QueuedTask> task){
    QuicWriterMutexLock lock(&task_mutex_);
    queued_tasks_.push_back(std::move(task));
}
void ClientThread::ExitGracefully(){
    if(active_clients_.size()==0){    
        return;
    }
    std::set<MyQuicToyClient*> clients;
    for(auto it=active_clients_.begin();it!=active_clients_.end();it++){
        MyQuicToyClient* c=(*it);
        clients.insert(c);
    }
    for(auto it=clients.begin();it!=clients.end();it++){
        (*it)->Disconnect();
    }
      
    std::deque<std::unique_ptr<QueuedTask>> tasks;
    {
        QuicWriterMutexLock lock(&task_mutex_);
        tasks.swap(queued_tasks_);
    }
    while(!tasks.empty()){
        tasks.front()->Run();
        tasks.pop_front();
    }       
}
void ClientThread::HandleInactiveClient(){
    while(!inactive_clients_.empty()){
        auto it=inactive_clients_.begin();
        MyQuicToyClient *client=(*it);
        inactive_clients_.erase(it);
        delete client;
    }
}
}
