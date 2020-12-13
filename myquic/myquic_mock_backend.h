#pragma once
#include "net/third_party/quiche/src/quic/myquic/myquic_channel.h"
#include "net/third_party/quiche/src/quic/core/quic_alarm.h"
#include <memory>
#include <atomic>
#include <set>
namespace quic{
class ServerEchoChannel :public MyQuicChannel{
 public:
  ServerEchoChannel(MyQuicTransportStream* stream):stream_(stream){}
  ~ServerEchoChannel(){}
  void OnCanRead() override;
  void OnFinRead() override;
  void OnCanWrite() override;
  void OnDestroy() override;
  bool SendData(const char *data,size_t size,bool fin) override{return false;}
  void set_channel_monitor(ChannelMonitor *monitor) override{monitor_=monitor;}
  void EchoBack();
 private:
  MyQuicTransportStream* stream_;
  ChannelMonitor *monitor_=nullptr;
  std::string buffer_;
  bool fin_=false;
  int read_bytes_=0;
};
class MockReadChannel:public MyQuicChannel{
public:
    MockReadChannel(MyQuicTransportStream* stream):stream_(stream){}
    ~MockReadChannel(){}
    void OnCanRead() override;
    void OnFinRead() override;
    void OnCanWrite() override;
    void OnDestroy() override;
    bool SendData(const char *data,size_t size,bool fin) override{return false;}
    void set_channel_monitor(ChannelMonitor *monitor) override{monitor_=monitor;} 
private:
    MyQuicTransportStream* stream_;
    ChannelMonitor *monitor_=nullptr;
};
class MockWriteChannel:public MyQuicChannel{
public:
    MockWriteChannel(MyQuicTransportStream* stream):stream_(stream){}
    ~MockWriteChannel(){}
    void OnCanRead() override;   
    void OnFinRead() override;
    void OnCanWrite() override ;
    void OnDestroy() override;
    bool SendData(const char *data,size_t size,bool fin) override;
    void set_channel_monitor(ChannelMonitor *monitor) override{monitor_=monitor;}     
private:
    MyQuicTransportStream* stream_;
    ChannelMonitor *monitor_=nullptr;
};


class MockEndpointMonitor{
public:
    virtual ~MockEndpointMonitor(){}
    virtual void OnEndpointDestroy(MyQuicEndpoint *endpoint)=0;
};
class MockClientPoint:public MyQuicEndpoint,
public MyQuicChannel::ChannelMonitor{
public:
    MockClientPoint(){}
    void OnSessionDestroy() override;
    void OnSessionReady(MyQuicTransportSessionInterface *session) override;
    void HandleIncomingStream(MyQuicTransportStream *stream) override;
    void OnChannelDestory(MyQuicChannel *channel) override;
    void set_endpoint_monitor(MockEndpointMonitor *monitor){monitor_=monitor;}
    void SendDataAlarm();
private:
    std::atomic<bool> session_ready_{false};
    int send_count_=0;
    std::unique_ptr<QuicAlarm> send_alarm_;
    MyQuicTransportSessionInterface *session_=nullptr;
    QuicAlarmFactory *alarm_factory_=nullptr;
    QuicClock *clock_=nullptr;
    MyQuicChannel *channel_ptr_=nullptr;
    int active_channel_=0;
    MockEndpointMonitor *monitor_=nullptr;
};

class MockServerPoint:public MyQuicEndpoint,
public MyQuicChannel::ChannelMonitor{
public:
    MockServerPoint(){}
    void OnSessionDestroy() override;
    void OnSessionReady(MyQuicTransportSessionInterface *session) override;
    void HandleIncomingStream(MyQuicTransportStream *stream) override;
    void OnChannelDestory(MyQuicChannel *channel) override;
    void set_endpoint_monitor(MockEndpointMonitor *monitor){monitor_=monitor;}
private:
    std::atomic<bool> session_ready_{false};
    MyQuicTransportSessionInterface *session_=nullptr;
    MyQuicChannel *echo_channel_=nullptr;
    MyQuicChannel *write_channel_=nullptr;
    int active_channel_=0;
    MockEndpointMonitor *monitor_=nullptr;
};

class MockClientBackend:public MyQuicBackend,
public MockEndpointMonitor{
public:
    ~MockClientBackend() override;
    void NotifyFailure(std::string indication,uint8_t id) override{}
    MyQuicEndpoint *CreateEndpoint(std::string indication,
                    MyQuicTransportSessionInterface *session) override;
    void OnEndpointDestroy(MyQuicEndpoint *endpoint) override;
private:
    std::set<MockClientPoint*> active_points_; 
    std::set<MockClientPoint*> inactive_points_;
}; 
class MockServerBackend :public MyQuicBackend,
public MockEndpointMonitor{
public:
    ~MockServerBackend() override;
    void NotifyFailure(std::string indication,uint8_t id) override{}
    MyQuicEndpoint *CreateEndpoint(std::string indication,
                    MyQuicTransportSessionInterface *session) override;
    void OnEndpointDestroy(MyQuicEndpoint *endpoint) override;
    void DebugInfo();
private:
    std::set<MockServerPoint*> active_points_; 
    std::set<MockServerPoint*> inactive_points_;
};
}
