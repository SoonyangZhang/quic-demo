// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.



#include <utility>
#include <vector>
#include "net/third_party/quiche/src/quic/myquic/myquic_toy_server.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/tools/quic_memory_cache_backend.h"

DEFINE_QUIC_COMMAND_LINE_FLAG(int32_t,
                              port,
                              6121,
                              "The port the quic server will listen on.");

DEFINE_QUIC_COMMAND_LINE_FLAG(bool,
                              quic_ietf_draft,
                              false,
                              "Only enable IETF draft versions. This also "
                              "enables required internal QUIC flags.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    quic_versions,
    "",
    "QUIC versions to enable, e.g. \"h3-25,h3-27\". If not set, then all "
    "available versions are enabled.");

namespace quic {



MyQuicToyServer::MyQuicToyServer(ServerFactory* server_factory)
    :server_factory_(server_factory) {}

int MyQuicToyServer::Start() {
  ParsedQuicVersionVector supported_versions;
  if (GetQuicFlag(FLAGS_quic_ietf_draft)) {
    QuicVersionInitializeSupportForIetfDraft();
    for (const ParsedQuicVersion& version : AllSupportedVersions()) {
      // Add all versions that supports IETF QUIC.
      if (version.HasIetfQuicFrames() &&
          version.handshake_protocol == quic::PROTOCOL_TLS1_3) {
        supported_versions.push_back(version);
      }
    }
  } else {
    supported_versions = AllSupportedVersions();
  }
  std::string versions_string = GetQuicFlag(FLAGS_quic_versions);
  if (!versions_string.empty()) {
    supported_versions = ParseQuicVersionVectorString(versions_string);
  }
  if (supported_versions.empty()) {
    return 1;
  }
  for (const auto& version : supported_versions) {
    QuicEnableVersion(version);
  }
  auto proof_source = quic::CreateDefaultProofSource();
  auto server=server_factory_->CreateServer(std::move(proof_source), supported_versions);
  server_=std::move(server);
  if (!server_->CreateUDPSocketAndListen(quic::QuicSocketAddress(
          quic::QuicIpAddress::Any6(), GetQuicFlag(FLAGS_port)))) {
    return 1;
  }
  return 0;
}
void  MyQuicToyServer::HandleEvent(){
    if(server_){
        server_->WaitForEvents();  
    }
}
void  MyQuicToyServer::Quit(){
    if(server_){
        server_->Shutdown();
    }
}
QuicEpollServer* MyQuicToyServer::epoll_server(){
    if(server_){
        return server_->epoll_server();
    }
    return nullptr;
}
}  // namespace quic
