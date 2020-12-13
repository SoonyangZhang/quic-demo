#include <vector>
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/tools/quic_epoll_server_factory.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_epoll.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_toy_server.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_mock_backend.h"
#include <signal.h>
#include <iostream>
namespace quic{
class MockQuicServerFactory : public MyQuicToyServer::ServerFactory {
 public:
  MockQuicServerFactory(MyQuicBackend*backend):backend_(backend){}
  std::unique_ptr<MyQuicServer> CreateServer(std::unique_ptr<ProofSource> proof_source,
      const quic::ParsedQuicVersionVector& supported_versions) override;

 private:
  MyQuicBackend *backend_;
};
std::unique_ptr<MyQuicServer> MockQuicServerFactory::CreateServer(std::unique_ptr<ProofSource> proof_source,
      const quic::ParsedQuicVersionVector& supported_versions){
  return std::make_unique<quic::MyQuicServer>(std::move(proof_source),
                                            backend_,
                                            supported_versions);    
}
}
static volatile bool m_running=true;
void signal_exit_handler(int sig)
{
	m_running=false;
} 
using namespace quic;
int main(int argc, char* argv[]) {
  const char* usage = "Usage: quic_server [options]";
  std::vector<std::string> non_option_args =
      quic::QuicParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }
  std::unique_ptr<quic::MyQuicBackend> backend(new quic::MockServerBackend());
  quic::MockQuicServerFactory server_factory(backend.get());
  quic::MyQuicToyServer server(&server_factory);
  if(server.Start()!=0){
      return 1;
  }
  while(m_running){
      server.HandleEvent();
  }
  server.Quit();
  quic::MockServerBackend *ptr=static_cast<quic::MockServerBackend*>(backend.get());
  ptr->DebugInfo();
  std::cout<<"server quit"<<std::endl;
  return 0;
}