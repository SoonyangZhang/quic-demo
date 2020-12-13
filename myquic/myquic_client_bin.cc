// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <signal.h>
#include "net/third_party/quiche/src/quic/myquic/myquic_mock_backend.h"
#include "net/third_party/quiche/src/quic/myquic/myquic_client_thread.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
static volatile bool m_running=true;
void signal_exit_handler(int sig)
{
	m_running=false;
} 
using namespace quic;
int main(int argc, char* argv[]) {
    signal(SIGTERM, signal_exit_handler);
    signal(SIGINT, signal_exit_handler);
    signal(SIGTSTP, signal_exit_handler);
    const char* usage = "Usage: quic_client [options]";
    quic::QuicParseCommandLineFlags(usage, argc, argv);
    //SetQuicReloadableFlag(quic_default_to_bbr,true);
    /*
    quic::QuicEpollServer epoll_server;
    quic::MyQuicEpollClientFactory factory(&epoll_server);
    quic::MyQuicToyClient client1(&factory);   
    quic::MyQuicToyClient client2(&factory);*/
    
    /*
    while(m_running&&!client.destroyed()){
        client.LoopOnce();      
    }*/
    
    
    /*uint64_t indication=0;
    int ret=client1.InitialAndConnect();    
    if(ret!=0){
            std::cout<<"client error exit"<<std::endl;
            return 1;
    }    
    while(m_running){
         epoll_server.WaitForEventsAndExecuteCallbacks();
    }
    indication=client1.SesssionIndication();
    client2.SesssionIndication(indication);
    ret=client2.InitialAndConnect();  
    if(ret!=0){
            std::cout<<"client error exit"<<std::endl;
            return 1;
    }     
    while(m_running){
         epoll_server.WaitForEventsAndExecuteCallbacks();
    }*/
    std::unique_ptr<MyQuicBackend> backend(new MockClientBackend());
    std::unique_ptr<ClientThread> client(new ClientThread(backend.get()));
    std::string indication1("client1");
    std::string indication2("client2");
    client->RequestClient(indication1,1);
    client->RequestClient(indication2,1);
    client->Start();
    while(m_running){
        
    }
    client->Quit();
   return 0;
}