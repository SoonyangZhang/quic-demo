#pragma once
#include <memory>
#include <string>
#include <set>
#include <deque>
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"
#include "net/third_party/quiche/src/quic/tools/quic_epoll_client_factory.h"
#include "net/third_party/quiche/src/quic/tools/quic_client.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_str_cat.h"

#include "net/third_party/quiche/src/quic/platform/api/quic_mutex.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_thread.h"

#include "net/third_party/quiche/src/quic/myquic/myquic_toy_client.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_client.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_channel.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_protocol.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_context.h"


namespace quic{
// Factory creating QuicClient instances.
class MyQuicClientFactory : public MyQuicToyClient::ClientFactory {
 public:
  MyQuicClientFactory(MyQuicContext *context,MyQuicBackend * backend)
  :context_(context),
  backend_(backend){}
  std::unique_ptr<MyQuicClient> CreateClient(
       QuicSession::Visitor *owner,
      std::string host_for_lookup,
      uint16_t port,
      ParsedQuicVersionVector versions,
      std::unique_ptr<ProofVerifier> verifier) override;
 private:  
    MyQuicContext *context_;
    MyQuicBackend *backend_;
};
class ClientThread:public MyQuicToyClient::ConnectionNotifier,
public QuicThread,
public MyQuicContext{
public:
    struct RequestClientConfig{
       RequestClientConfig(const char*indication,size_t size,uint8_t request,QuicIpAddress ip);
       uint8_t id;
       char join_indication[kMaxJoinIndicationSize];
       size_t length;
       QuicIpAddress local;
    };

    ClientThread(MyQuicBackend *backend);
    ~ClientThread();
    void Run() override;
    void Quit();
    void RequestClient(std::string &indication,int id,QuicIpAddress local=QuicIpAddress());    
    void OnConnectionClosed(MyQuicToyClient *client,
                            quic::QuicErrorCode error,
                          const std::string& error_details) override;  



    QuicClock *clock() override;
    QuicAlarmFactory* alarm_factory()  override;
    QuicEpollServer* epoll_server()   override;
    base::PlatformThreadId context_id()  override{return context_id_;}
    void PostInnerTask(std::unique_ptr<QueuedTask> task) override;   
    private:
    void ExitGracefully();
    void HandleInactiveClient();
    MyQuicBackend *backend_;
    mutable QuicMutex request_mutex_;
    std::deque<RequestClientConfig> requests_;
    std::set<MyQuicToyClient*> active_clients_;
    std::set<MyQuicToyClient*> inactive_clients_;
    std::unique_ptr<MyQuicClientFactory> factory_;
    std::unique_ptr<QuicEpollServer> epoll_server_;
    std::unique_ptr<QuicAlarmFactory> alarm_factory_;
    std::unique_ptr<QuicClock> clock_;
    mutable QuicMutex task_mutex_;
    std::deque<std::unique_ptr<QueuedTask>>  queued_tasks_;
    base::PlatformThreadId context_id_=base::kInvalidThreadId;
    QuicNotification quit_;
};
}
