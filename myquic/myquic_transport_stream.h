// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstddef>
#include <memory>

#include "absl/strings/string_view.h"

#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_session_interface.h"

namespace quic {

// MyQuicTransportStream is an extension of QuicStream that provides I/O interface
// that is safe to use in the QuicTransport context.  The interface ensures no
// application data is processed before the client indication is processed.
class QUIC_EXPORT_PRIVATE MyQuicTransportStream : public QuicStream {
 public:
  class QUIC_EXPORT_PRIVATE Visitor {
   public:
    virtual ~Visitor() {}
    virtual void OnCanRead() = 0;
    virtual void OnFinRead() = 0;
    virtual void OnCanWrite() = 0;
    virtual void OnDestroy()=0;
  };

  MyQuicTransportStream(QuicStreamId id,
                      QuicSession* session,
                      MyQuicTransportSessionInterface* session_interface);
  ~MyQuicTransportStream();
  // Reads at most |buffer_size| bytes into |buffer| and returns the number of
  // bytes actually read.
  size_t Read(char* buffer, size_t buffer_size);
  // Reads all available data and appends it to the end of |output|.
  size_t Read(std::string* output);
  // Writes |data| into the stream.  Returns true on success.
  ABSL_MUST_USE_RESULT bool Write(absl::string_view data);
  ABSL_MUST_USE_RESULT bool Write(const char*data,size_t size,bool fin);
  // Sends the FIN on the stream.  Returns true on success.
  ABSL_MUST_USE_RESULT bool SendFin();

  // Indicates whether it is possible to write into stream right now.
  bool CanWrite() const;
  // Indicates the number of bytes that can be read from the stream.
  size_t ReadableBytes() const;

  // QuicSession method implementations.
  void OnDataAvailable() override;
  void OnCanWriteNewData() override;
  void set_visitor(std::unique_ptr<Visitor> visitor) {
    visitor_ =std::move(visitor);
  }
  MyQuicTransportSessionInterface* session_interface() {return session_interface_;}
 protected:
  void MaybeNotifyFinRead();

  MyQuicTransportSessionInterface* session_interface_;
  std::unique_ptr<Visitor> visitor_ = nullptr;
  bool fin_read_notified_ = false;
};
}  // namespace quic

