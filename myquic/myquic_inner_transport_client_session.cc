// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/myquic/myquic_inner_transport_client_session.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "url/gurl.h"
#include "net/third_party/quiche/src/quic/core/quic_constants.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_data_writer.h"
#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_protocol.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_protocol.h"
namespace quic {
MyQuicInnerTransportClientSession::MyQuicInnerTransportClientSession(
    QuicConnection* connection,
    Visitor* owner,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const GURL& url,
    QuicCryptoClientConfig* crypto_config,
    url::Origin origin,
    MyQuicBackend *backend,
    MyQuicContext *context,
    std::string &indication)
    : QuicSession(connection,
                  owner,
                  config,
                  supported_versions,
                  /*num_expected_unidirectional_static_streams*/ 0),
      url_(url),
      origin_(origin),
      backend_(backend),
      context_(context),
      join_indication_(indication){
  for (const ParsedQuicVersion& version : supported_versions) {
    QUIC_BUG_IF(version.handshake_protocol != PROTOCOL_TLS1_3)
        << "QuicTransport requires TLS 1.3 handshake";
  }
  std::cout<<"uni: "<<config.GetMaxUnidirectionalStreamsToSend()<<std::endl;
  std::cout<<"bi: "<<config.GetMaxBidirectionalStreamsToSend()<<std::endl;
  crypto_stream_ = std::make_unique<QuicCryptoClientStream>(
      QuicServerId(url.host(), url.EffectiveIntPort()), this,
      crypto_config->proof_verifier()->CreateDefaultContext(), crypto_config,
      /*proof_handler=*/this, /*has_application_state = */ true);
    if(!endpoint_){
        endpoint_=backend_->CreateEndpoint(join_indication_,this);
    }
    if(!endpoint_){
    connection->CloseConnection(
        QUIC_INTERNAL_ERROR, "Create Endpoint Failed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);      
    }      
}
MyQuicInnerTransportClientSession::~MyQuicInnerTransportClientSession(){
    if(endpoint_){
        endpoint_->OnSessionDestroy();
    }
    endpoint_=nullptr;
}
void MyQuicInnerTransportClientSession::OnAlpnSelected(
    quiche::QuicheStringPiece alpn) {
  // Defense in-depth: ensure the ALPN selected is the desired one.
  if (alpn != QuicTransportAlpn()) {
    QUIC_BUG << "QuicTransport negotiated non-QuicTransport ALPN: " << alpn;
    connection()->CloseConnection(
        QUIC_INTERNAL_ERROR, "QuicTransport negotiated non-QuicTransport ALPN",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  alpn_received_ = true;
}
QuicStream* MyQuicInnerTransportClientSession::CreateIncomingStream(QuicStreamId id) {
  QUIC_DVLOG(1) << "Creating incoming QuicTransport stream " << id;
  MyQuicTransportStream* stream = CreateStream(id);
  OnIncomingDataStream(stream);
  return stream;
}
void MyQuicInnerTransportClientSession::OnIncomingDataStream(MyQuicTransportStream* stream){
    if(endpoint_){
        endpoint_->HandleIncomingStream(stream);
    }else{
        CloseTransportSession();        
    }
}
void MyQuicInnerTransportClientSession::SetDefaultEncryptionLevel(
    EncryptionLevel level) {
  QuicSession::SetDefaultEncryptionLevel(level);
  if (level == ENCRYPTION_FORWARD_SECURE) {
     SendIndication();    
  }
}

void MyQuicInnerTransportClientSession::OnTlsHandshakeComplete() {
  QuicSession::OnTlsHandshakeComplete();
  SendIndication();
}

MyQuicTransportStream*
MyQuicInnerTransportClientSession::OpenOutgoingBidirectionalStream() {
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    QUIC_BUG << "Attempted to open a stream in violation of flow control";
    return nullptr;
  }
  return CreateStream(GetNextOutgoingBidirectionalStreamId());
}

MyQuicTransportStream*
MyQuicInnerTransportClientSession::OpenOutgoingUnidirectionalStream() {
  if (!CanOpenNextOutgoingUnidirectionalStream()) {
    QUIC_BUG << "Attempted to open a stream in violation of flow control";
    return nullptr;
  }
  return CreateStream(GetNextOutgoingUnidirectionalStreamId());
}

MyQuicTransportStream* MyQuicInnerTransportClientSession::CreateStream(QuicStreamId id) {
  auto stream = std::make_unique<MyQuicTransportStream>(id, this, this);
  MyQuicTransportStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}

std::string MyQuicInnerTransportClientSession::SerializeClientIndication(){
  uint8_t type=INDI_REQ;
  size_t  content_size=join_indication_.length();
  const size_t buffer_size=2+content_size;
  std::string buffer;
  buffer.resize(buffer_size);
  QuicDataWriter writer(buffer.size(), &buffer[0]);
  bool success =
      writer.WriteUInt8(type)&&
      writer.WriteUInt8(static_cast<uint8_t>(content_size))&&
      writer.WriteBytes(join_indication_.data(),join_indication_.length());
  QUIC_BUG_IF(!success) << "Failed to serialize client indication";
  QUIC_BUG_IF(writer.length() != buffer.length())
      << "Serialized client indication has length different from expected";
  return buffer;
}

void MyQuicInnerTransportClientSession::SendIndication() {
  if (!crypto_stream_->encryption_established()) {
    QUIC_BUG << "Client indication may only be sent once the encryption is "
                "established.";
    connection()->CloseConnection(
        QUIC_INTERNAL_ERROR, "Attempted to send client indication unencrypted",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  if (ready_) {
    QUIC_BUG << "Client indication may only be sent once.";
    connection()->CloseConnection(
        QUIC_INTERNAL_ERROR, "Attempted to send client indication twice",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  QuicStreamId id=GetNextOutgoingBidirectionalStreamId();
  auto client_indication_owned = std::make_unique<ClientIndication>(
      /*stream_id=*/id, this,
      /*is_static=*/false, StreamType::BIDIRECTIONAL);
  QUIC_BUG_IF(client_indication_owned->id() != MyQuicClientIndicationStream())
      << "Client indication stream is " << client_indication_owned->id()
      << " instead of expected " << MyQuicClientIndicationStream();
  ClientIndication* client_indication = client_indication_owned.get();
  ActivateStream(std::move(client_indication_owned));

  client_indication->WriteOrBufferData(SerializeClientIndication(),
                                       /*fin=*/true, nullptr);
  // Defense in depth: never set the ready bit unless ALPN has been confirmed.
  if (!alpn_received_) {
    QUIC_BUG << "ALPN confirmation missing after handshake complete";
    connection()->CloseConnection(
        QUIC_INTERNAL_ERROR,
        "ALPN confirmation missing after handshake complete",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  // Don't set the ready bit if we closed the connection due to any error
  // beforehand.
  if (!connection()->connected()) {
    return;
  }
  ready_ = true;
  if(endpoint_){
      endpoint_->OnSessionReady(this);
  }
}
void MyQuicInnerTransportClientSession::OnJoinIndication(std::string indication){   
}
void MyQuicInnerTransportClientSession::ClientIndication::OnDataAvailable(){
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
            MyQuicInnerTransportClientSession *session=
            (MyQuicInnerTransportClientSession*)(QuicStream::session());
            session->OnJoinIndication(indication);
	    std::string null_str;
            null_str.swap(buffer_);             
        }   
    }
    if (sequencer()->IsClosed()) {
        OnFinRead();
    }
}
void MyQuicInnerTransportClientSession::OnMessageReceived(
    quiche::QuicheStringPiece message) {
    //visitor_->OnDatagramReceived(message);
}

void MyQuicInnerTransportClientSession::OnCanCreateNewOutgoingStream(
    bool unidirectional) {
  /*if (unidirectional) {
    visitor_->OnCanCreateNewOutgoingUnidirectionalStream();
  } else {
    visitor_->OnCanCreateNewOutgoingBidirectionalStream();
  }*/
}
void MyQuicInnerTransportClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void MyQuicInnerTransportClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}
        
MyQuicTransportStream* MyQuicInnerTransportClientSession::RequestBidirectionalStream(){
    return OpenOutgoingBidirectionalStream();
}
MyQuicTransportStream* MyQuicInnerTransportClientSession::RequestWriteStream(){
    return OpenOutgoingUnidirectionalStream();
}    
void MyQuicInnerTransportClientSession::CloseTransportSession(){
    if(connection()&&connection()->connected()){
        connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY,
        "Session disconnecting",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);        
    }
}
const QuicConnectionStats& MyQuicInnerTransportClientSession::GetStats(){
    return connection()->GetStats();
}
bool MyQuicInnerTransportClientSession::InSlowStart() const{
    bool in_slow_start=false;
    if(connection()&&connection()->connected()){
        in_slow_start=connection()->sent_packet_manager().InSlowStart();
    }
    return in_slow_start;
}
}  // namespace quic
