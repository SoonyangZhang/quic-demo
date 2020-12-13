#pragma once
#include <string>
#include "net/third_party/quiche/src/quic/core/crypto/crypto_handshake.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/tools/quic_client_base.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "net/third_party/quiche/src/quic/tools/quic_client_base.h"
#include "net/third_party/quiche/src/quic/tools/quic_client_epoll_network_helper.h"
#include "net/third_party/quiche/src/quic/core/quic_connection_stats.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_client_session.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"
namespace quic{
class MyQuicClient:public QuicClientBase{
public:
    class Requester{
        public:
        virtual const std::string & RequestJoinIndication()=0;
        virtual ~Requester(){}
    };
  // These will create their own QuicClientEpollNetworkHelper.
  MyQuicClient(QuicSession::Visitor *owner,
             QuicSocketAddress server_address,
             const QuicServerId& server_id,
             const ParsedQuicVersionVector& supported_versions,
             MyQuicContext *context,
             MyQuicBackend *backend,
             std::unique_ptr<ProofVerifier> proof_verifier);
  MyQuicClient(QuicSession::Visitor *owner,
             QuicSocketAddress server_address,
             const QuicServerId& server_id,
             const ParsedQuicVersionVector& supported_versions,
             const QuicConfig& config,
             MyQuicContext *context,
             MyQuicBackend *backend,  
             std::unique_ptr<QuicClientEpollNetworkHelper> network_helper,
             std::unique_ptr<ProofVerifier> proof_verifier,
             std::unique_ptr<SessionCache> session_cache);
    ~MyQuicClient() override {}
    MyQuicContext* GetContext() {return context_;}
    bool IsSessionReady() const {return session_ready_;}
    MyQuicTransportClientSession * client_session();
    bool AsynConnect();
    void set_requester(Requester * requester){requester_=requester;}    
protected:
  // Takes ownership of |connection|.
  std::unique_ptr<QuicSession> CreateQuicClientSession(
      const quic::ParsedQuicVersionVector& supported_versions,
      QuicConnection* connection) override;  

    int GetNumSentClientHellosFromSession() override;
    int GetNumReceivedServerConfigUpdatesFromSession() override;
    
    // This client does not resend saved data. This will be a no-op.
    void ResendSavedData() override{}
    
    // This client does not resend saved data. This will be a no-op.
    void ClearDataToResend() override{}
  
    bool EarlyDataAccepted() override;
    bool ReceivedInchoateReject() override;
private: 
    bool HasActiveRequests() override{return false;}
    MyQuicContext *context_;
    MyQuicBackend *backend_;
    QuicSession::Visitor *owner_=nullptr;
    Requester *requester_=nullptr;
    bool session_ready_=false;
};
}
