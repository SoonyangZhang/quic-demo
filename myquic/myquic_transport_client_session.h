#pragma once
#include "net/third_party/quiche/src/quic/myquic/myquic_inner_transport_client_session.h"

#include <memory>
#include <utility>
namespace quic{
class MyQuicTransportClientSession:public MyQuicInnerTransportClientSession{
public:
    MyQuicTransportClientSession(
    std::unique_ptr<QuicConnection> connection,
    Visitor* owner,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicCryptoClientConfig* crypto_config,
    QuicServerId server_id,
    const GURL& url,
    url::Origin origin,
    MyQuicBackend *backend,
    MyQuicContext *context,
    std::string &indication);
    ~MyQuicTransportClientSession(){}
   void Initialize() override; 
   int GetNumSentClientHellos() const;
   int GetNumReceivedServerConfigUpdates() const;  
    bool EarlyDataAccepted() const;
    bool ReceivedInchoateReject() const;   
private:
    std::unique_ptr<QuicConnection> connection_;
};   
}
