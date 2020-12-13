#pragma once 
// for indication
#include "net/third_party/quiche/src/quic/myquic/myquic_protocol.h"
#include "net/third_party/quiche/src/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_epoll.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_server_session.h"
namespace quic{
class MyQuicDispatcher : public QuicDispatcher{
public:
    MyQuicDispatcher(
        const QuicConfig* config,
        const QuicCryptoServerConfig* crypto_config,
        QuicVersionManager* version_manager,
        MyQuicContext *context,
        MyQuicBackend *backend,
        std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
        uint8_t expected_server_connection_id_length);
    
    ~MyQuicDispatcher() override;
    
    int GetRstErrorCount(QuicRstStreamErrorCode rst_error_code) const;
    
    void OnRstStreamReceived(const QuicRstStreamFrame& frame) override;
    //GetSupportedVersions OnConnectionClosed  OnWriteBlocked OnStopSendingReceived
protected:
  std::unique_ptr<QuicSession> CreateQuicSession(
      QuicConnectionId server_connection_id,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address,
      quiche::QuicheStringPiece alpn,
      const ParsedQuicVersion& version) override;
private:
    MyQuicContext *context_;
    MyQuicBackend *backend_;
    // The map of the reset error code with its counter.
    std::map<QuicRstStreamErrorCode, int> rst_error_map_;
};
}
