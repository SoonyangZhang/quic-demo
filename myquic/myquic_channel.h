#pragma once
#include <stdint.h>
#include <memory>
#include <string>
#include "net/third_party/quiche/src/quic/platform/api/quic_epoll.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_mutex.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"
namespace quic{
class MyQuicChannel:public MyQuicTransportStream::Visitor{
public:
    class ChannelMonitor{
        public:
        virtual ~ChannelMonitor(){}
        virtual void OnChannelDestory(MyQuicChannel *channel)=0;
    };
    virtual ~MyQuicChannel(){}
    virtual bool SendData(const char *data,size_t size,bool fin)=0;
    virtual void set_channel_monitor(ChannelMonitor *monitor)=0;
};
class BidirectionalChannel:public MyQuicChannel{
public:    
    BidirectionalChannel(MyQuicTransportStream* stream);
    ~BidirectionalChannel(){} 
    
    //MyQuicTransportStream::Visitor
    void OnCanRead() override;
    void OnFinRead() override;
    void OnCanWrite() override;
    void OnDestroy() override;    
    bool SendData(const char *data,size_t size,bool fin) override;
    void set_channel_monitor(ChannelMonitor *monitor) override{monitor_=monitor;}
    //format: fin(uint8_t)+len(uint32_t)+data  for asyn buffer;
private:
    MyQuicTransportStream* stream_=nullptr;
    ChannelMonitor *monitor_=nullptr;
    std::string buffer_;
    int read_bytes_=0;
};
class MyQuicTransportSessionInterface;
class MyQuicEndpoint{
public:
    virtual ~MyQuicEndpoint(){}
    virtual void OnSessionReady(MyQuicTransportSessionInterface *session)=0;
    virtual void OnSessionDestroy()=0;
    virtual void HandleIncomingStream(MyQuicTransportStream *stream)=0;
};
class MyQuicBackend{
public:
    virtual ~MyQuicBackend(){}
    virtual void NotifyFailure(std::string indication,uint8_t id)=0;
    virtual MyQuicEndpoint *CreateEndpoint(std::string indication,
                            MyQuicTransportSessionInterface *session)=0;    
};    
}
