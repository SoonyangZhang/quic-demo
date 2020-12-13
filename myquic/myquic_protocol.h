#pragma  once
#include <stdint.h>
#include "net/third_party/quiche/src/quic/core/quic_types.h"
namespace quic{
namespace{
const size_t kMaxJoinIndicationSize=16;    
}
enum IndicationType:uint8_t{
    INDI_REQ,
    INDI_RES,
};
constexpr QuicByteCount MyJoinIndicationMaxSize(){
    return kMaxJoinIndicationSize;
}
// The stream ID on which the client indication is sent.
QUIC_EXPORT_PRIVATE constexpr QuicStreamId MyQuicClientIndicationStream() {
  return 0;
}
}
