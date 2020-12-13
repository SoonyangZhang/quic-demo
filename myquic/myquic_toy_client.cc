// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/myquic/myquic_toy_client.h"

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"
#include "net/third_party/quiche/src/quic/tools/fake_proof_verifier.h"
#include "net/third_party/quiche/src/quic/tools/quic_url.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_text_utils.h"

namespace {

using quic::QuicUrl;
using quiche::QuicheStringPiece;
using quiche::QuicheTextUtils;

}  // namespace

DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    host,
    "",
    "The IP or hostname to connect to. If not provided, the host "
    "will be derived from the provided URL.");

DEFINE_QUIC_COMMAND_LINE_FLAG(int32_t, port, 0, "The port to connect to.");






DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    quic_version,
    "",
    "QUIC version to speak, e.g. 21. If not set, then all available "
    "versions are offered in the handshake. Also supports wire versions "
    "such as Q043 or T099.");

DEFINE_QUIC_COMMAND_LINE_FLAG(bool,
                              quic_ietf_draft,
                              false,
                              "Use the IETF draft version. This also enables "
                              "required internal QUIC flags.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    version_mismatch_ok,
    false,
    "If true, a version mismatch in the handshake is not considered a "
    "failure. Useful for probing a server to determine if it speaks "
    "any version of QUIC.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    force_version_negotiation,
    false,
    "If true, start by proposing a version that is reserved for version "
    "negotiation.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    redirect_is_success,
    true,
    "If true, an HTTP response code of 3xx is considered to be a "
    "successful response, otherwise a failure.");

DEFINE_QUIC_COMMAND_LINE_FLAG(int32_t,
                              initial_mtu,
                              0,
                              "Initial MTU of the connection.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    int32_t,
    num_requests,
    1,
    "How many sequential requests to make on a single connection.");

DEFINE_QUIC_COMMAND_LINE_FLAG(bool,
                              disable_certificate_verification,
                              false,
                              "If true, don't verify the server certificate.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    drop_response_body,
    false,
    "If true, drop response body immediately after it is received.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    bool,
    disable_port_changes,
    false,
    "If true, do not change local port after each request.");

namespace quic {
MyQuicToyClient::MyQuicToyClient(ClientFactory* client_factory)
    :client_factory_(client_factory){}
MyQuicToyClient::~MyQuicToyClient(){
    if(client_){
        client_->Disconnect();
    }
}
int MyQuicToyClient::InitialAndConnect() {
  std::string host = GetQuicFlag(FLAGS_host);
  if (host.empty()) {
    return 1;
  }
  int port = GetQuicFlag(FLAGS_port);
  if (port == 0) {
    return 1;
  }

  quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();

  std::string quic_version_string = GetQuicFlag(FLAGS_quic_version);
  if (GetQuicFlag(FLAGS_quic_ietf_draft)) {
    quic::QuicVersionInitializeSupportForIetfDraft();
    versions = {};
    for (const ParsedQuicVersion& version : AllSupportedVersions()) {
      if (version.HasIetfQuicFrames() &&
          version.handshake_protocol == quic::PROTOCOL_TLS1_3) {
        versions.push_back(version);
      }
    }
    quic::QuicEnableVersion(versions[0]);

  } else if (!quic_version_string.empty()) {
    quic::ParsedQuicVersion parsed_quic_version =
        quic::ParseQuicVersionString(quic_version_string);
    if (parsed_quic_version.transport_version ==
        quic::QUIC_VERSION_UNSUPPORTED) {
      return 1;
    }
    versions = {parsed_quic_version};
    quic::QuicEnableVersion(parsed_quic_version);
  }

  if (GetQuicFlag(FLAGS_force_version_negotiation)) {
    versions.insert(versions.begin(),
                    quic::QuicVersionReservedForNegotiation());
  }

  std::unique_ptr<quic::ProofVerifier> proof_verifier=std::make_unique<FakeProofVerifier>();
  // Build the client, and try to connect.
  client_= client_factory_->CreateClient(this,
       host, port, versions, std::move(proof_verifier));

  if (client_ == nullptr){
    std::cerr << "Failed to create client." << std::endl;
    return 1;
  }
  client_->set_requester(this);
  if(bind_to_address_.IsInitialized()){
    std::cout<<"bind addr "<<bind_to_address_<<std::endl;
    client_->set_bind_to_address(bind_to_address_); 
  }
  
  int32_t initial_mtu = GetQuicFlag(FLAGS_initial_mtu);
  client_->set_initial_max_packet_length(
      initial_mtu != 0 ? initial_mtu : quic::kDefaultMaxPacketSize);
  if (!client_->Initialize()) {
    std::cerr << "Failed to initialize client." << std::endl;
    return 1;
  }
  //cofigure epoll, 50ms unwanted.
  //client_->epoll_server()->set_timeout_in_us(0);
  /*if (!client_->Connect()) {
    quic::QuicErrorCode error = client_->session()->error();
    if (error == quic::QUIC_INVALID_VERSION) {
      std::cerr << "Server talks QUIC, but none of the versions supported by "
                << "this client: " << ParsedQuicVersionVectorToString(versions)
                << std::endl;
      // 0: No error.
      // 20: Failed to connect due to QUIC_INVALID_VERSION.
      return GetQuicFlag(FLAGS_version_mismatch_ok) ? 0 : 20;
    }
    std::cerr << "Failed to connect to " << host << ":" << port
              << ". Error: " << quic::QuicErrorCodeToString(error) << std::endl;
    return 1;
  }*/
  client_->AsynConnect();
  //std::cerr << "Connected to " << host << ":" << port << std::endl;
  return 0;
}
/*void MyQuicToyClient::LoopOnce(){
    if(client_->connected()){
        //client_->WaitForEvents();
        client_->epoll_server()->WaitForEventsAndExecuteCallbacks();
    }      
}*/
void MyQuicToyClient::Disconnect(){
    if(client_){
        client_->Disconnect();
    }
}
void MyQuicToyClient::OnConnectionClosed(quic::QuicConnectionId server_connection_id,
                        quic::QuicErrorCode error,
                        const std::string& error_details,
                        quic::ConnectionCloseSource source){
    Disconnect();
    notifier_->OnConnectionClosed(this,error,error_details);
}
void MyQuicToyClient::set_notifier(ConnectionNotifier *notifier){
    notifier_=notifier;
}
}  // namespace quic
