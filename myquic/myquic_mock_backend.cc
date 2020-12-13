#include <string>
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_mock_backend.h"
namespace quic{
void ServerEchoChannel::OnCanRead() {
  bool success = stream_->Read(&buffer_);
  DCHECK(success);
  read_bytes_+=buffer_.size();
  EchoBack();
}

void ServerEchoChannel::OnFinRead() {
  QUIC_DVLOG(1) << "Finished receiving data on stream " << stream_->id()
                << ", queueing up the echo";
 fin_=true;
 stream_->TryCloseReadSide();
}
void ServerEchoChannel::OnCanWrite() {
    std::cout<<"on serer can write"<<std::endl;
}
void ServerEchoChannel::OnDestroy(){
    std::cout<<"server read "<<read_bytes_<<std::endl;
    if(monitor_){
        monitor_->OnChannelDestory(this);
    }     
}
void ServerEchoChannel::EchoBack(){
  stream_->Write(buffer_.data(),buffer_.length(),fin_);
  std::string null_str;
  null_str.swap(buffer_);
}

void MockReadChannel::OnCanRead(){
  std::string buffer;
  bool success = stream_->Read(&buffer);
  DCHECK(success);
  std::cout<<"mock read: "<<buffer.size()<<std::endl;
}

void MockReadChannel::OnFinRead()  {
  QUIC_DVLOG(1) << "Finished receiving data on stream " << stream_->id();
  stream_->TryCloseReadSide();
}
void MockReadChannel::OnCanWrite()  { QUIC_NOTREACHED(); }
void MockReadChannel::OnDestroy() {
    if(monitor_){
        monitor_->OnChannelDestory(this);
    }    
    std::cout<<"MockReadChannel dtor"<<std::endl;
}
void MockWriteChannel::OnCanRead()  {
  std::string buffer;
  bool success = stream_->Read(&buffer);
  DCHECK(success);
}
void MockWriteChannel::OnFinRead()  {
  QUIC_DVLOG(1) << "Finished receiving data on stream " << stream_->id();
  stream_->TryCloseReadSide();
}
void MockWriteChannel::OnCanWrite()  { QUIC_NOTREACHED(); }
void MockWriteChannel::OnDestroy()  {
    if(monitor_){
        monitor_->OnChannelDestory(this);
    }     
    std::cout<<"MockWriteChannel dtor"<<std::endl;
}
bool MockWriteChannel::SendData(const char *data,size_t size,bool fin) {
  stream_->Write(data,size,fin); 
  return true;      
}


class SendTestDataDelegate: public QuicAlarm::Delegate{
public:
    SendTestDataDelegate(MockClientPoint *client){
         client_=client;
    }
    ~SendTestDataDelegate() override{}
    void OnAlarm() override{
        client_->SendDataAlarm();
    }
private:
    MockClientPoint* client_;
};

void MockClientPoint::OnSessionDestroy(){
    session_ready_ =false;
    session_=nullptr;
    std::cout<<"MockClientPoint dtor"<<std::endl;
    if(send_alarm_){
        send_alarm_->Cancel();
    } 
    if(monitor_){
        monitor_->OnEndpointDestroy(this);
    }
}
void MockClientPoint::OnSessionReady(MyQuicTransportSessionInterface *session){
    session_=session;
    session_ready_=true;
    alarm_factory_=session_->GetContext()->alarm_factory();
    clock_=session_->GetContext()->clock();
    MyQuicTransportStream *stream=session_->RequestBidirectionalStream();
    CHECK(stream);
    std::unique_ptr<MyQuicChannel> channel(new BidirectionalChannel(stream));
    channel->set_channel_monitor(this);
    channel_ptr_=channel.get();
    stream->set_visitor(std::move(channel));
    active_channel_++;
    send_alarm_.reset(alarm_factory_->CreateAlarm(new SendTestDataDelegate(this)));
    send_alarm_->Update(clock_->ApproximateNow(),QuicTime::Delta::Zero());
}
void MockClientPoint::HandleIncomingStream(MyQuicTransportStream *stream){
    switch(stream->type()){
        case BIDIRECTIONAL:{
            std::unique_ptr<MyQuicChannel> channel(new BidirectionalChannel(stream));
            active_channel_++;
            channel->set_channel_monitor(this);
            stream->set_visitor(std::move(channel));
            break;
        }
        case READ_UNIDIRECTIONAL:{
            std::unique_ptr<MyQuicChannel> channel(new MockReadChannel(stream));
            active_channel_++;
            channel->set_channel_monitor(this);
            stream->set_visitor(std::move(channel));
            break;            
        }
        default:{
            QUIC_NOTREACHED();
            break;
        }
    }    
}
void MockClientPoint::OnChannelDestory(MyQuicChannel *channel){
    if(active_channel_>0){
        active_channel_--;
    }
    if(channel_ptr_==channel){
        std::cout<<"client destroy bi channel"<<std::endl;
        channel_ptr_=nullptr;
    }
    if((active_channel_==0)&&session_ready_&&session_){
        session_->CloseTransportSession();
        session_ready_=false;
    }
}
const int MockDataSize=3000;
void MockClientPoint::SendDataAlarm(){
    send_count_++;  
    std::string data;
    data.resize(MockDataSize);
    for(int i=0;i<MockDataSize;i++){
        data[i]='a';
    }
    bool fin=true;
    if(send_count_<=40){
        fin=false;
        if(session_ready_){
           send_alarm_->Update(clock_->ApproximateNow()+QuicTime::Delta::FromMilliseconds(500),
                                QuicTime::Delta::Zero());
        }
    }else{
        if(send_alarm_){
            send_alarm_->Cancel();
        }
    }
    if(session_ready_&&session_&&channel_ptr_){
        channel_ptr_->SendData(data.data(),data.size(),fin);
    }
}



void MockServerPoint::OnSessionDestroy(){
    session_ready_ =false;
    session_=nullptr;
    std::cout<<"MockServerPoint dtor"<<std::endl;
    if(monitor_){
        monitor_->OnEndpointDestroy(this);
    }
}
void MockServerPoint::OnSessionReady(MyQuicTransportSessionInterface *session){
    session_=session;
    session_ready_=true;
    MyQuicTransportStream *stream=session_->RequestWriteStream();
    CHECK(stream);
    std::unique_ptr<MyQuicChannel> channel(new MockWriteChannel(stream));
    channel->set_channel_monitor(this);
    write_channel_=channel.get();
    stream->set_visitor(std::move(channel));
    active_channel_++;
    std::string data("server say hi");
    write_channel_->SendData(data.data(),data.size(),true);
}
void MockServerPoint::HandleIncomingStream(MyQuicTransportStream *stream){
    switch(stream->type()){
        case BIDIRECTIONAL:{
            std::unique_ptr<MyQuicChannel> channel(new ServerEchoChannel(stream));
            active_channel_++;
            channel->set_channel_monitor(this);
            echo_channel_=channel.get();
            stream->set_visitor(std::move(channel));
            break;
        }
        case READ_UNIDIRECTIONAL:{
            std::unique_ptr<MyQuicChannel> channel(new MockReadChannel(stream));
            active_channel_++;
            channel->set_channel_monitor(this);
            stream->set_visitor(std::move(channel));
            break;            
        }
        default:{
            QUIC_NOTREACHED();
            break;
        }
    }    
}
void MockServerPoint::OnChannelDestory(MyQuicChannel *channel){
    if(active_channel_>0){
        active_channel_--;
    }
    if(echo_channel_==channel){
        std::cout<<"server destroy echo channel"<<std::endl;
        echo_channel_=nullptr;
    }
    if(channel==write_channel_){
        std::cout<<"server destroy write channel"<<std::endl;
        write_channel_=nullptr;
    }
    if((active_channel_==0)&&session_ready_&&session_){
        session_->CloseTransportSession();
        session_ready_=false;
    }
}
MockClientBackend::~MockClientBackend(){
    std::cout<<"bk active "<<active_points_.size()<<std::endl;
    std::cout<<"bk inactive "<<inactive_points_.size()<<std::endl;
    while(!inactive_points_.empty()){
        auto it=inactive_points_.begin();
        MockClientPoint *point=(*it);
        inactive_points_.erase(it);
        delete point;
    }
}
MyQuicEndpoint *MockClientBackend::CreateEndpoint(std::string indication,MyQuicTransportSessionInterface *session){
    MockClientPoint *point=new MockClientPoint();
    point->set_endpoint_monitor(this);
    active_points_.insert(point);
    return point;
}
void MockClientBackend::OnEndpointDestroy(MyQuicEndpoint *endpoint){
    MockClientPoint *point=(MockClientPoint*)endpoint;
    auto it=active_points_.find(point);
    if(it!=active_points_.end()){
        active_points_.erase(it);
    }
    inactive_points_.insert(point);
}

MockServerBackend::~MockServerBackend(){
    while(!inactive_points_.empty()){
        auto it=inactive_points_.begin();
        MockServerPoint *point=(*it);
        inactive_points_.erase(it);
        delete point;
    }    
}
void MockServerBackend::DebugInfo(){
    std::cout<<"bk active "<<active_points_.size()<<std::endl;
    std::cout<<"bk inactive "<<inactive_points_.size()<<std::endl;    
}
MyQuicEndpoint *MockServerBackend::CreateEndpoint(std::string indication,MyQuicTransportSessionInterface *session){
    MockServerPoint *point=new MockServerPoint();
    point->set_endpoint_monitor(this);
    active_points_.insert(point);
    return point;                        
}
void MockServerBackend::OnEndpointDestroy(MyQuicEndpoint *endpoint){
    std::cout<<"destroy endpoint "<<std::endl;
    MockServerPoint *point=(MockServerPoint*)endpoint;
    auto it=active_points_.find(point);
    if(it!=active_points_.end()){
        active_points_.erase(it);
    }
    inactive_points_.insert(point);
}
}
