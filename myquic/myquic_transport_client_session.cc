#include "net/third_party/quiche/src/quic/myquic/myquic_transport_client_session.h"
namespace quic{
MyQuicTransportClientSession::MyQuicTransportClientSession(
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
    std::string &indication):
    MyQuicInnerTransportClientSession(connection.get(),
    owner,config,supported_versions,url,
    crypto_config,origin,backend,context,indication),
    connection_(std::move(connection)){
    crypto_stream_.reset(new QuicCryptoClientStream(
      server_id,
      this,
      crypto_config->proof_verifier()->CreateDefaultContext(), crypto_config,
      /*proof_handler=*/this, /*has_application_state = */ true
    ));   
    }
void MyQuicTransportClientSession::Initialize(){
    MyQuicInnerTransportClientSession::Initialize();
    CryptoConnect();
}   
int MyQuicTransportClientSession::GetNumSentClientHellos() const{
    return crypto_stream_->num_sent_client_hellos();
}
int MyQuicTransportClientSession::GetNumReceivedServerConfigUpdates() const{
    return crypto_stream_->num_scup_messages_received();
}
bool MyQuicTransportClientSession::EarlyDataAccepted() const {
  return crypto_stream_->EarlyDataAccepted();
}

bool MyQuicTransportClientSession::ReceivedInchoateReject() const {
  return crypto_stream_->ReceivedInchoateReject();
}
}
