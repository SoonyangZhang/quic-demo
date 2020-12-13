#include "net/third_party/quiche/src/quic/myquic/myquic_channel.h"
#include "net/third_party/quiche/src/quic/core/quic_data_writer.h"
#include "net/third_party/quiche/src/quic/core/quic_data_reader.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include <iostream>
namespace quic{
bool AsynBufferParser(const char* buffer,size_t buffer_size,uint8_t *is_fin,uint32_t *len){
    *is_fin=0;
    *len=0;
    if(buffer_size>(sizeof(uint8_t)+sizeof(uint32_t))){
        QuicDataReader reader(buffer,buffer_size);
        bool success=reader.ReadUInt8(is_fin)&&
        reader.ReadUInt32(len);
        QUIC_BUG_IF(!success) << "Failed to deserialize asyn data";          
        if(success){
            return true;
        }
    } 
    return false;   
}
BidirectionalChannel::BidirectionalChannel(MyQuicTransportStream* stream)
:stream_(stream){}
bool BidirectionalChannel::SendData(const char *data,size_t size,bool fin){
    return stream_->Write(data,size,fin);   
}
void BidirectionalChannel::OnCanRead()  {
  bool success = stream_->Read(&buffer_);
  DCHECK(success);
  read_bytes_+=buffer_.size();
  std::string null_str;
  null_str.swap(buffer_);
}

void BidirectionalChannel::OnFinRead()  {
  QUIC_DVLOG(1) << "Finished receiving data on stream " << stream_->id()
                << ", queueing up the echo";
    stream_->TryCloseReadSide();
}
void BidirectionalChannel::OnCanWrite()  { 
    std::cout<<"on can write new data"<<std::endl;   

}
void BidirectionalChannel::OnDestroy(){
    std::cout<<"server read "<<read_bytes_<<std::endl;    
    if(monitor_){
        monitor_->OnChannelDestory(this);
    }
}
}
