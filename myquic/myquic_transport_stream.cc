// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"

#include <sys/types.h>

#include "net/third_party/quiche/src/quic/core/quic_buffer_allocator.h"
#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include <iostream>
namespace quic {

MyQuicTransportStream::MyQuicTransportStream(
    QuicStreamId id,
    QuicSession* session,
    MyQuicTransportSessionInterface* session_interface)
    : QuicStream(id,
                 session,
                 /*is_static=*/false,
                 QuicUtils::GetStreamType(id,
                                          session->connection()->perspective(),
                                          session->IsIncomingStream(id),
                                          session->version())),
      session_interface_(session_interface) {}
MyQuicTransportStream::~MyQuicTransportStream(){
    if(visitor_){
        visitor_->OnDestroy();
    }
}
size_t MyQuicTransportStream::Read(char* buffer, size_t buffer_size) {
  if (!session_interface_->IsSessionReady()) {
    return 0;
  }

  iovec iov;
  iov.iov_base = buffer;
  iov.iov_len = buffer_size;
  const size_t result = sequencer()->Readv(&iov, 1);
  if (sequencer()->IsClosed()) {
    MaybeNotifyFinRead();
  }
  return result;
}

size_t MyQuicTransportStream::Read(std::string* output) {
  const size_t old_size = output->size();
  const size_t bytes_to_read = ReadableBytes();
  output->resize(old_size + bytes_to_read);
  size_t bytes_read = Read(&(*output)[old_size], bytes_to_read);
  DCHECK_EQ(bytes_to_read, bytes_read);
  output->resize(old_size + bytes_read);
  return bytes_read;
}

bool MyQuicTransportStream::Write(quiche::QuicheStringPiece data) {
  if (!CanWrite()) {
    return false;
  }

  QuicUniqueBufferPtr buffer = MakeUniqueBuffer(
      session()->connection()->helper()->GetStreamSendBufferAllocator(),
      data.size());
  memcpy(buffer.get(), data.data(), data.size());
  QuicMemSlice memslice(std::move(buffer), data.size());
  QuicConsumedData consumed =
      WriteMemSlices(QuicMemSliceSpan(&memslice), /*fin=*/false);

  if (consumed.bytes_consumed == data.size()) {
    return true;
  }
  if (consumed.bytes_consumed == 0) {
    return false;
  }
  QUIC_BUG << "WriteMemSlices() unexpectedly partially consumed the input "
              "data, provided: "
           << data.size() << ", written: " << consumed.bytes_consumed;
  OnUnrecoverableError(
      QUIC_INTERNAL_ERROR,
      "WriteMemSlices() unexpectedly partially consumed the input data");
  return false;
}
bool MyQuicTransportStream::Write(const char*data,size_t size,bool fin){
    if(!data&&fin){
        return SendFin();
    }
    if (!CanWrite()) {
    return false;
    }
  QuicUniqueBufferPtr buffer = MakeUniqueBuffer(
      session()->connection()->helper()->GetStreamSendBufferAllocator(),
      size);
  memcpy(buffer.get(), data,size);
  QuicMemSlice memslice(std::move(buffer), size);
  QuicConsumedData consumed =
      WriteMemSlices(QuicMemSliceSpan(&memslice),fin);

  if (consumed.bytes_consumed ==size) {
    return true;
  }
  if (consumed.bytes_consumed == 0) {
    return false;
  }
  QUIC_BUG << "WriteMemSlices() unexpectedly partially consumed the input "
              "data, provided: "
           << size << ", written: " << consumed.bytes_consumed;
  OnUnrecoverableError(
      QUIC_INTERNAL_ERROR,
      "WriteMemSlices() unexpectedly partially consumed the input data");
  return false;    
}
bool MyQuicTransportStream::SendFin() {
  if (!CanWrite()) {
    return false;
  }

  QuicMemSlice empty;
  QuicConsumedData consumed =
      WriteMemSlices(QuicMemSliceSpan(&empty), /*fin=*/true);
  DCHECK_EQ(consumed.bytes_consumed, 0u);
  return consumed.fin_consumed;
}

bool MyQuicTransportStream::CanWrite() const {
  return session_interface_->IsSessionReady() && CanWriteNewData() &&
         !write_side_closed();
}

size_t MyQuicTransportStream::ReadableBytes() const {
  if (!session_interface_->IsSessionReady()) {
    return 0;
  }

  return sequencer()->ReadableBytes();
}

void MyQuicTransportStream::OnDataAvailable() {
  if (sequencer()->IsClosed()) {
    MaybeNotifyFinRead();
    return;
  }

  if (visitor_ == nullptr) {
    return;
  }
  if (ReadableBytes() == 0) {
    return;
  }
  visitor_->OnCanRead();
}

void MyQuicTransportStream::OnCanWriteNewData() {
  // Ensure the origin check has been completed, as the stream can be notified
  // about being writable before that.
  if (!CanWrite()) {
    return;
  }
  if (visitor_ != nullptr) {
    visitor_->OnCanWrite();
  }
}
void MyQuicTransportStream::TryCloseReadSide(){
    CloseReadSide();
}
void MyQuicTransportStream::MaybeNotifyFinRead() {
  if (visitor_ == nullptr || fin_read_notified_) {
    return;
  }
  fin_read_notified_ = true;
  visitor_->OnFinRead();
  OnFinRead();
}
}  // namespace quic
