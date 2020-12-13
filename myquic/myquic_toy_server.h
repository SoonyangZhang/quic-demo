// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include <memory>
#include "net/third_party/quiche/src/quic/core/crypto/proof_source.h"
#include "net/third_party/quiche/src/quic/tools/quic_spdy_server_base.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_protocol.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_transport_stream.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_server.h"
namespace quic {

// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.
class MyQuicToyServer {
 public:
  // A factory for creating MyQuicServer instances.
  class ServerFactory {
   public:
    virtual ~ServerFactory() = default;

    // Creates a MyQuicServer instance using |backend| for generating
    // responses, and |proof_source| for certificates.
    virtual std::unique_ptr<MyQuicServer> CreateServer(std::unique_ptr<ProofSource> proof_source,
                                const ParsedQuicVersionVector& supported_versions) = 0;
  };


  // Constructs a new toy server that will use |server_factory| to create the
  // actual MyQuicServer instance.
  MyQuicToyServer(ServerFactory* server_factory);

  // Connects to the QUIC server based on the various flags defined in the
  // .cc file, listends for requests and sends the responses. Returns 1 on
  // failure and does not return otherwise.
  int  Start();
  void  HandleEvent();
  void  Quit();
  QuicEpollServer* epoll_server();
 private:
    ServerFactory* server_factory_;    // Unowned. 
    std::unique_ptr<MyQuicServer>  server_;  
};

}  // namespace quic

