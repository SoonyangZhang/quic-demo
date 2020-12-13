#include "net/third_party/quiche/src/quic/myquic/myquic_client.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_epoll_connection_helper.h"
#include "net/third_party/quiche/src/quic/core/quic_epoll_alarm_factory.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/core/quic_data_writer.h"
#include "net/third_party/quiche/src/quic/core/quic_data_reader.h"
#include "url/gurl.h"
#include "url/origin.h"
#include <iostream>
namespace quic{
const char* kTestOrigin = "https://test-origin.test";
url::Origin GetTestOrigin() {
  GURL origin_url(kTestOrigin);
  return url::Origin::Create(origin_url);
}
MyQuicClient::MyQuicClient(QuicSession::Visitor *owner,
                        QuicSocketAddress server_address,
                       const QuicServerId& server_id,
                       const ParsedQuicVersionVector& supported_versions,
                       MyQuicContext *context,
                       MyQuicBackend *backend,
                       std::unique_ptr<ProofVerifier> proof_verifier)
    : MyQuicClient(owner,
          server_address,
          server_id,
          supported_versions,
          QuicConfig(),
          context,
          backend,
          QuicWrapUnique(new QuicClientEpollNetworkHelper(context->epoll_server(), this)),
          std::move(proof_verifier),
          nullptr) {}

MyQuicClient::MyQuicClient(QuicSession::Visitor *owner,
    QuicSocketAddress server_address,
    const QuicServerId& server_id,
    const ParsedQuicVersionVector& supported_versions,
    const QuicConfig& config,
    MyQuicContext *context,
    MyQuicBackend *backend,
    std::unique_ptr<QuicClientEpollNetworkHelper> network_helper,
    std::unique_ptr<ProofVerifier> proof_verifier,
    std::unique_ptr<SessionCache> session_cache): QuicClientBase(
          server_id,
          supported_versions,
          config,
          new QuicEpollConnectionHelper(context->epoll_server(), QuicAllocator::SIMPLE),
          new QuicEpollAlarmFactory(context->epoll_server()),
          std::move(network_helper),
          std::move(proof_verifier),
          std::move(session_cache)) {
  set_server_address(server_address);
  context_=context;
  backend_=backend;
  owner_=owner;
}
std::unique_ptr<QuicSession> MyQuicClient::CreateQuicClientSession(
    const quic::ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection) {
    auto port=server_address().port();
    auto url=GURL("quic-transport://test.example.com:"+std::to_string(port));
    auto origin=GetTestOrigin();    
    std::unique_ptr<QuicConnection> wrap_connection(connection);
    CHECK(requester_);
    std::string indication=requester_->RequestJoinIndication();
    MyQuicTransportClientSession *session=new MyQuicTransportClientSession(std::move(wrap_connection),
    owner_,*config(), supported_versions, crypto_config(),server_id(),
    url,origin,backend_,context_,indication);
    return std::unique_ptr<MyQuicTransportClientSession>(session);
} 
int MyQuicClient::GetNumSentClientHellosFromSession(){
    return client_session()->GetNumSentClientHellos();
}
int MyQuicClient::GetNumReceivedServerConfigUpdatesFromSession(){
    return client_session()->GetNumReceivedServerConfigUpdates();
}
bool MyQuicClient::EarlyDataAccepted() {
  return client_session()->EarlyDataAccepted();
}

bool MyQuicClient::ReceivedInchoateReject() {
  return client_session()->ReceivedInchoateReject();
}
MyQuicTransportClientSession * MyQuicClient::client_session(){
    return static_cast<MyQuicTransportClientSession*>(QuicClientBase::session());
}
bool MyQuicClient::AsynConnect(){
  if (!connected()){
    StartConnect();
  }
  if (session() == nullptr) {
    QUIC_BUG << "Missing session after Connect";
    return false;
  }
  return session()->connection()->connected();    
}
}
