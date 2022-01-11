// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdint>
#include <memory>
#include "absl/strings/string_view.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_client_config.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_containers.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_protocol.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_session_interface.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_channel.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_epoll.h"
namespace quic {

// A client session for the QuicTransport protocol.
class QUIC_EXPORT_PRIVATE MyQuicInnerTransportClientSession
    : public QuicSession,
      public MyQuicTransportSessionInterface,
      public QuicCryptoClientStream::ProofHandler {
 public:
  MyQuicInnerTransportClientSession(QuicConnection* connection,
                             Visitor* owner,
                             const QuicConfig& config,
                             const ParsedQuicVersionVector& supported_versions,
                             const GURL& url,
                             QuicCryptoClientConfig* crypto_config,
                             url::Origin origin,
                             MyQuicBackend *backend,
                             MyQuicContext *context,
                             std::string &indication);
  ~MyQuicInnerTransportClientSession();
  std::vector<std::string> GetAlpnsToOffer() const override {
    return std::vector<std::string>({QuicTransportAlpn()});
  }
  void OnAlpnSelected(absl::string_view alpn) override;
  bool alpn_received() const { return alpn_received_; }

  void CryptoConnect() { crypto_stream_->CryptoConnect(); }

  bool ShouldKeepConnectionAlive() const override { return true; }

  QuicCryptoStream* GetMutableCryptoStream() override {
    return crypto_stream_.get();
  }
  const QuicCryptoStream* GetCryptoStream() const override {
    return crypto_stream_.get();
  }
  
  MyQuicContext* GetContext() override {return context_;} 
  MyQuicTransportStream* RequestBidirectionalStream() override;
  MyQuicTransportStream* RequestWriteStream() override;  
  // Returns true once the encryption has been established and the client
  // indication has been sent.  No application data will be read or written
  // before the connection is ready.  Once the connection becomes ready, this
  // method will never return false.
  bool IsSessionReady() const override { return ready_; }  
  std::string JoinIndication() const  override{return join_indication_;}
  void  JoinIndication(std::string indication)  override {join_indication_=indication;}  
  void CloseTransportSession() override;
  const QuicConnectionStats& GetStats() override;  
  bool InSlowStart() const override;  
  
  QuicStream* CreateIncomingStream(QuicStreamId id) override;
  QuicStream* CreateIncomingStream(PendingStream* /*pending*/) override {
    QUIC_BUG << "MyQuicInnerTransportClientSession::CreateIncomingStream("
                "PendingStream) not implemented";
    return nullptr;
  }

  void SetDefaultEncryptionLevel(EncryptionLevel level) override;
  void OnTlsHandshakeComplete() override;
  void OnMessageReceived(absl::string_view message) override;

  
  using QuicSession::CanOpenNextOutgoingBidirectionalStream;
  using QuicSession::CanOpenNextOutgoingUnidirectionalStream;

  MyQuicTransportStream* OpenOutgoingBidirectionalStream() ;
  MyQuicTransportStream* OpenOutgoingUnidirectionalStream();

  using QuicSession::datagram_queue;

  // QuicCryptoClientStream::ProofHandler implementation.
  void OnProofValid(const QuicCryptoClientConfig::CachedState& cached) override;
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) override;
  void OnJoinIndication(std::string indication);
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
  void OnIncomingDataStream(MyQuicTransportStream* /*stream*/);
  // Serializes the client indication as described in
  // https://vasilvv.github.io/webtransport/draft-vvv-webtransport-quic.html#rfc.section.3.2
  std::string SerializeClientIndication();
  // Creates the client indication stream and sends the client indication on it.
  void SendIndication();
  void OnCanCreateNewOutgoingStream(bool unidirectional) override;
  std::unique_ptr<QuicCryptoClientStream> crypto_stream_;
  GURL url_;
  url::Origin origin_;
  MyQuicBackend *backend_;
  MyQuicContext *context_;
  std::string join_indication_;
  MyQuicEndpoint *endpoint_=nullptr;
  bool alpn_received_ = false;
  bool ready_ = false;
};

}  // namespace quic

