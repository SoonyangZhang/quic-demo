# quic-demo
test quic transport  
it depends on [naiveproxy](https://github.com/klzgrad/naiveproxy). (v89.0.4389.72)   
1 Put myquic file under net/third_party/quiche/src/quic/.  
2 Find the postion of epoll_quic_server in BUILD.gn under (net/third_party/quiche), add three conponnets(myquic_main, myquic_client,myquic_server).  
```
  executable("myquic_main") {
    sources = [
      "src/quic/myquic/mylog_main.cc",
    ]
    deps = [
      "//base",
      "//net",
    ]
  }
  executable("myquic_client") {
    sources = [
      "src/quic/myquic/myquic_client_bin.cc",
      "src/quic/myquic/myquic_toy_client.h",
      "src/quic/myquic/myquic_toy_client.cc",
      "src/quic/myquic/myquic_client_thread.h",
      "src/quic/myquic/myquic_client_thread.cc",
      "src/quic/myquic/myquic_client.h",
      "src/quic/myquic/myquic_client.cc",
    ]
    deps = [
      "//base",
      "//net",
      "//net:epoll_quic_tools",
      "//net:epoll_server",
      "//net:simple_quic_tools",
      "//third_party/boringssl",
    ]
  }
  executable("myquic_server") {
    sources = [
      "src/quic/myquic/myquic_server_bin.cc",
      "src/quic/myquic/myquic_toy_server.h",
      "src/quic/myquic/myquic_toy_server.cc",
      "src/quic/myquic/myquic_server.h",
      "src/quic/myquic/myquic_server.cc",
    ]
    deps = [
      "//base",
      "//net",
      "//net:epoll_quic_tools",
      "//net:epoll_server",
      "//net:simple_quic_tools",
      "//third_party/boringssl",
    ]
  }    
```
3 
```
open /net/third_party/quiche/BUILD.gn
```  
add the source files to source files of simple_quic_tools_core:  
``` 
    "src/quic/myquic/myquic_channel.h",
    "src/quic/myquic/myquic_channel.cc",
    "src/quic/myquic/myquic_context.h",
    "src/quic/myquic/myquic_inner_transport_client_session.h",
    "src/quic/myquic/myquic_inner_transport_client_session.cc",
    "src/quic/myquic/myquic_mock_backend.cc",
    "src/quic/myquic/myquic_mock_backend.h",
    "src/quic/myquic/myquic_protocol.h",
    "src/quic/myquic/myquic_dispatcher.h",
    "src/quic/myquic/myquic_dispatcher.cc",
    "src/quic/myquic/myquic_transport_client_session.h",
    "src/quic/myquic/myquic_transport_client_session.cc",
    "src/quic/myquic/myquic_transport_server_session.h",
    "src/quic/myquic/myquic_transport_server_session.cc",
    "src/quic/myquic/myquic_transport_session_interface.h",
    "src/quic/myquic/myquic_transport_stream.h",
    "src/quic/myquic/myquic_transport_stream.cc",    
```
4 In src/build.sh, add:  
```
ninja -C "$out" naive  quic_client quic_server myquic_server myquic_client  
```
5 Test:  
```
cd net/tools/quic/certs
./generate-certs.sh   
```
          
```
./out/Release/myquic_server \
  --certificate_file=net/tools/quic/certs/out/leaf_cert.pem \
  --key_file=net/tools/quic/certs/out/leaf_cert.pkcs8  
```
     
```
./out/Release/myquic_client --host=127.0.0.1 --port=6121    
```
