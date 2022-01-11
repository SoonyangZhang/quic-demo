#pragma once
#include "net/third_party/quiche/src/quic/myquic/myquic_client.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
namespace quic {
class MyQuicToyClient
    :public QuicSession::Visitor,
    public  MyQuicClient::Requester{
 public:
  class ClientFactory {
   public:
    virtual ~ClientFactory() = default;

    // Creates a new client configured to connect to |host_for_lookup:port|
    // supporting |versions|, using |host_for_handshake| for handshake and
    // |verifier| to verify proofs.
    virtual std::unique_ptr<MyQuicClient> CreateClient(
        QuicSession::Visitor *owner,
        std::string host_for_lookup,
        uint16_t port,
        ParsedQuicVersionVector versions,
        std::unique_ptr<ProofVerifier> verifier) = 0;
  };
  class ConnectionNotifier{
    public:
      virtual ~ConnectionNotifier(){}
      virtual void OnConnectionClosed(MyQuicToyClient *client,
                            quic::QuicErrorCode error,
                          const std::string& error_details)=0;                        
  };
  void Disconnect();
  int InitialAndConnect();
  
  MyQuicToyClient(ClientFactory* client_factory);
  ~MyQuicToyClient();
  // QuicSession::Visitor methods.
  void OnConnectionClosed(quic::QuicConnectionId server_connection_id,
                          quic::QuicErrorCode error,
                          const std::string& error_details,
                          quic::ConnectionCloseSource source) override;
  void OnWriteBlocked(
      quic::QuicBlockedWriterInterface* /*blocked_writer*/) override {}
  void OnRstStreamReceived(const quic::QuicRstStreamFrame& /*frame*/) override {
  }
  void OnStopSendingReceived(
      const quic::QuicStopSendingFrame& /*frame*/) override {}
  virtual void OnNewConnectionIdSent(
      const QuicConnectionId& server_connection_id,
      const QuicConnectionId& new_connection_id) override {}

  // Called when a ConnectionId has been retired.
  virtual void OnConnectionIdRetired(
      const QuicConnectionId& server_connection_id) override {}
  void set_bind_to_address(QuicIpAddress address) {
    bind_to_address_ = address;
  }
  void set_notifier(ConnectionNotifier *notifier);
  void JoinIndication(std::string &indication){indication_=indication;}
  const std::string & RequestJoinIndication() override{return indication_;}
 private:
  ClientFactory* client_factory_;
  std::unique_ptr<MyQuicClient> client_;
  QuicIpAddress bind_to_address_; 
  ConnectionNotifier* notifier_;
  std::string indication_;
};

}  // namespace quic

