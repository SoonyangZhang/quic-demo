#include "net/third_party/quiche/src/quic/myquic/myquic_dispatcher.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_server_session.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "net/third_party/quiche/src/quic/core/quic_epoll_alarm_factory.h"
#include "net/third_party/quiche/src/quic/core/quic_epoll_connection_helper.h"
namespace quic {

MyQuicDispatcher::MyQuicDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    MyQuicContext *context,
    MyQuicBackend *backend,
    std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
    uint8_t expected_server_connection_id_length)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::make_unique<QuicEpollConnectionHelper>
                     (context->epoll_server(),QuicAllocator::BUFFER_POOL),                     
                     std::move(session_helper),
                     std::make_unique<QuicEpollAlarmFactory>(context->epoll_server()), 
                     expected_server_connection_id_length),
                     context_(context),
                     backend_(backend){}
MyQuicDispatcher::~MyQuicDispatcher() = default;

int MyQuicDispatcher::GetRstErrorCount(
    QuicRstStreamErrorCode error_code) const {
  auto it = rst_error_map_.find(error_code);
  if (it == rst_error_map_.end()) {
    return 0;
  }
  return it->second;
}

void MyQuicDispatcher::OnRstStreamReceived(
    const QuicRstStreamFrame& frame) {
  auto it = rst_error_map_.find(frame.error_code);
  if (it == rst_error_map_.end()) {
    rst_error_map_.insert(std::make_pair(frame.error_code, 1));
  } else {
    it->second++;
  }
}

std::unique_ptr<QuicSession> MyQuicDispatcher::CreateQuicSession(
      QuicConnectionId server_connection_id,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address,
      absl::string_view /*alpn*/,
      const ParsedQuicVersion& version) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  std::unique_ptr<QuicConnection> connection;
  connection.reset(new QuicConnection(
      server_connection_id,self_address, peer_address, helper(), alarm_factory(), writer(),
      /* owns_writer= */ false, Perspective::IS_SERVER,
      ParsedQuicVersionVector{version}));

  auto session = std::make_unique<MyQuicTransportServerSession>(std::move(connection),this,
      config(), GetSupportedVersions(),crypto_config(), compressed_certs_cache(),
      backend_,context_);
  session->Initialize();
  return session;
}

}  // namespace quic
