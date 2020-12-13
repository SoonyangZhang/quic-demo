#pragma once
#include <stdint.h>
#include <string>
#include "net/third_party/quiche/src/quic/core/quic_connection_stats.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_context.h"
namespace quic{
class MyQuicTransportStream;
class QUIC_EXPORT_PRIVATE MyQuicTransportSessionInterface {
 public:
  virtual ~MyQuicTransportSessionInterface() {}
  virtual MyQuicContext* GetContext()=0;
  virtual std::string JoinIndication() const =0;
  virtual void  JoinIndication(std::string indication)=0;
  virtual bool IsSessionReady() const = 0;
  virtual MyQuicTransportStream * RequestBidirectionalStream()=0;
  virtual MyQuicTransportStream * RequestWriteStream()=0;
  virtual void CloseTransportSession()=0;
  virtual const QuicConnectionStats& GetStats()=0;
  virtual bool InSlowStart() const=0;
};    
}
