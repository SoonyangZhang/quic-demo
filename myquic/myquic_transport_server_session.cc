// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/myquic/myquic_transport_server_session.h"

#include <algorithm>
#include <memory>
#include <string>

#include "url/gurl.h"
#include "url/url_constants.h"
#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/core/quic_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_protocol.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_str_cat.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include <iostream>
namespace quic {

namespace {
class QuicTransportServerCryptoHelper
    : public QuicCryptoServerStreamBase::Helper {
 public:
  bool CanAcceptClientHello(const CryptoHandshakeMessage& /*message*/,
                            const QuicSocketAddress& /*client_address*/,
                            const QuicSocketAddress& /*peer_address*/,
                            const QuicSocketAddress& /*self_address*/,
                            std::string* /*error_details*/) const override {
    return true;
  }
};

}  // namespace
MyQuicTransportServerSession::MyQuicTransportServerSession(
    std::unique_ptr<QuicConnection> connection,
    Visitor* owner,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    MyQuicBackend *backend,
    MyQuicContext *context)
    : QuicSession(connection.get(),
                  owner,
                  config,
                  supported_versions,
                  /*num_expected_unidirectional_static_streams*/ 0),
                   backend_(backend),
                   context_(context){
  for (const ParsedQuicVersion& version : supported_versions){
    QUIC_BUG_IF(version.handshake_protocol != PROTOCOL_TLS1_3)
        << "QuicTransport requires TLS 1.3 handshake";
  }
  std::cout<<"uni: "<<config.GetMaxUnidirectionalStreamsToSend()<<std::endl;
  std::cout<<"bi: "<<config.GetMaxBidirectionalStreamsToSend()<<std::endl;
  static QuicTransportServerCryptoHelper* helper =
      new QuicTransportServerCryptoHelper();
  crypto_stream_ = CreateCryptoServerStream(
      crypto_config, compressed_certs_cache, this, helper);
   connection_own_=std::move(connection);
}
MyQuicTransportServerSession::~MyQuicTransportServerSession(){
    if(endpoint_){
        endpoint_->OnSessionDestroy();
    }
    endpoint_=nullptr;    
    std::cout<<"MyQuicTransportServerSession dtor"<<std::endl;
}
QuicStream* MyQuicTransportServerSession::CreateIncomingStream(QuicStreamId id) {
  if (id == MyQuicClientIndicationStream()) {
    auto indication = std::make_unique<ClientIndication>(MyQuicClientIndicationStream(),this,false,
    StreamType::BIDIRECTIONAL);
    ClientIndication* indication_ptr = indication.get();
    ActivateStream(std::move(indication));
    return indication_ptr;
  }
  auto stream = std::make_unique<MyQuicTransportStream>(id, this, this);
  MyQuicTransportStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  OnIncomingDataStream(stream_ptr);
  return stream_ptr;
}
void MyQuicTransportServerSession::ClientIndication::OnDataAvailable() {
    sequencer()->Read(&buffer_);
    if(buffer_.length()>2){
        QuicDataReader reader(buffer_.data(),buffer_.length());
        uint8_t type;
        uint8_t content_size=0;
        bool success=reader.ReadUInt8(&type)&&
        reader.ReadUInt8(&content_size);
        QUIC_BUG_IF(!success) << "Failed to parser indication";
        if(success&&(buffer_.length()>=2+content_size)){
            const char *data=buffer_.data();
            data+=2;
            std::string indication(data,(size_t)content_size);
            MyQuicTransportServerSession *session=
            (MyQuicTransportServerSession*)(QuicStream::session());
            session->OnJoinIndication(indication);
            std::string reply;
            reply.swap(buffer_);
            reply[0]=INDI_RES;
            absl::string_view view(reply.data(),reply.size());
            WriteOrBufferData(view,true,nullptr);              
        }   
    }    
    if (sequencer()->IsClosed()) {
        OnFinRead();
    }
}
MyQuicTransportStream*
MyQuicTransportServerSession::OpenOutgoingBidirectionalStream() {
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    QUIC_BUG << "Attempted to open a stream in violation of flow control";
    return nullptr;
  }
  return CreateStream(GetNextOutgoingBidirectionalStreamId());
}

MyQuicTransportStream*
MyQuicTransportServerSession::OpenOutgoingUnidirectionalStream() {
  if (!CanOpenNextOutgoingUnidirectionalStream()) {
    QUIC_BUG << "Attempted to open a stream in violation of flow control";
    return nullptr;
  }
  return CreateStream(GetNextOutgoingUnidirectionalStreamId());
}
MyQuicTransportStream* MyQuicTransportServerSession::CreateStream(QuicStreamId id) {
  auto stream = std::make_unique<MyQuicTransportStream>(id, this, this);
  MyQuicTransportStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}
void MyQuicTransportServerSession::OnJoinIndication(std::string indication){
  ready_ = true;
  join_indication_=indication;
  OnSessionReady();
}
void MyQuicTransportServerSession::OnIncomingDataStream(MyQuicTransportStream* stream){
    if(endpoint_){
        endpoint_->HandleIncomingStream(stream);
    }else{
        CloseTransportSession();        
    }
}
void MyQuicTransportServerSession::OnSessionReady(){
    if(endpoint_){return ;}
    endpoint_=backend_->CreateEndpoint(join_indication_,this);
    if(!endpoint_){
        connection()->CloseConnection(
        QUIC_INTERNAL_ERROR, "Create Endpoint Failed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);      
    }else{
        endpoint_->OnSessionReady(this);
    }    
}
MyQuicTransportStream* MyQuicTransportServerSession::RequestBidirectionalStream(){
    return OpenOutgoingBidirectionalStream();
}
MyQuicTransportStream* MyQuicTransportServerSession::RequestWriteStream(){
    return OpenOutgoingUnidirectionalStream();
}
void MyQuicTransportServerSession::CloseTransportSession(){
    if(connection()&&connection()->connected()){
        connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY,
        "Session disconnecting",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);        
    }
}
const QuicConnectionStats& MyQuicTransportServerSession::GetStats(){
    return connection()->GetStats();
}
bool MyQuicTransportServerSession::InSlowStart() const{
    bool in_slow_start=false;
    if(connection()&&connection()->connected()){
        in_slow_start=connection()->sent_packet_manager().InSlowStart();
    }
    return in_slow_start;
}
}  // namespace quic
