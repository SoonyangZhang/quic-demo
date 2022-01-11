// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include "absl/strings/string_view.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_server_stream_base.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_protocol.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_session_interface.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_protocol.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_channel.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_epoll.h"
namespace quic {

// A server session for the QuicTransport protocol.
class QUIC_EXPORT_PRIVATE MyQuicTransportServerSession
    : public QuicSession,
      public MyQuicTransportSessionInterface{
 public:
  MyQuicTransportServerSession(std::unique_ptr<QuicConnection> connection,
                             Visitor* owner,
                             const QuicConfig& config,
                             const ParsedQuicVersionVector& supported_versions,
                             const QuicCryptoServerConfig* crypto_config,
                             QuicCompressedCertsCache* compressed_certs_cache,
                             MyQuicBackend *backend,
                             MyQuicContext *context);
  virtual ~MyQuicTransportServerSession();
  std::vector<absl::string_view>::const_iterator SelectAlpn(
      const std::vector<absl::string_view>& alpns) const override {
    return std::find(alpns.cbegin(), alpns.cend(), QuicTransportAlpn());
  }

  bool ShouldKeepConnectionAlive() const override { return true; }

  QuicCryptoServerStreamBase* GetMutableCryptoStream() override {
    return crypto_stream_.get();
  }
  const QuicCryptoServerStreamBase* GetCryptoStream() const override {
    return crypto_stream_.get();
  }
  
  MyQuicContext* GetContext() override {return context_;} 
  MyQuicTransportStream* RequestBidirectionalStream() override;
  MyQuicTransportStream* RequestWriteStream() override; 
  // Returns true once the encryption has been established, the client
  // indication has been received and the origin has been verified.  No
  // application data will be read or written before the connection is ready.
  // Once the connection becomes ready, this method will never return false.
  bool IsSessionReady() const override { return ready_; }
  std::string JoinIndication() const  override{return join_indication_;}
  void  JoinIndication(std::string indication)  override {join_indication_=indication;}
  void CloseTransportSession() override;
  const QuicConnectionStats& GetStats() override;
  bool InSlowStart() const override;
  
  QuicStream* CreateIncomingStream(QuicStreamId id) override;
  QuicStream* CreateIncomingStream(PendingStream* /*pending*/) override {
    QUIC_BUG << "MyQuicTransportServerSession::CreateIncomingStream("
                "PendingStream) not implemented";
    return nullptr;
  }

  using QuicSession::CanOpenNextOutgoingBidirectionalStream;
  using QuicSession::CanOpenNextOutgoingUnidirectionalStream;

  MyQuicTransportStream* OpenOutgoingBidirectionalStream() ;
  MyQuicTransportStream* OpenOutgoingUnidirectionalStream();  
  void  OnJoinIndication(std::string indication);

 protected:
  class QUIC_EXPORT_PRIVATE ClientIndication : public QuicStream {
   public:
    using QuicStream::QuicStream;
    ~ClientIndication() override{}
    void OnDataAvailable() override;
    private: 
    std::string buffer_;
  };
  // Creates and activates a MyQuicTransportStream for the given ID.
  MyQuicTransportStream* CreateStream(QuicStreamId id);
  virtual void OnIncomingDataStream(MyQuicTransportStream* /*stream*/);
  virtual void OnSessionReady();
  std::unique_ptr<QuicConnection> connection_own_;
  MyQuicBackend *backend_;
  MyQuicContext *context_;
  MyQuicEndpoint *endpoint_=nullptr; 
  std::unique_ptr<QuicCryptoServerStreamBase> crypto_stream_;
  bool ready_ = false;
  std::string join_indication_;
  
};

}  // namespace quic

