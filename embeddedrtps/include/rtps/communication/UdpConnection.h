/*
The MIT License
Copyright (c) 2019 Lehrstuhl Informatik 11 - RWTH Aachen University
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE

This file is part of embeddedRTPS.

Author: i11 - Embedded Software, RWTH Aachen University
*/

#ifndef RTPS_UDPCONNECTION_H
#define RTPS_UDPCONNECTION_H

#include <cstdint>

#ifndef EMBRTPS_USE_SOCKETS
#include "TcpipCoreLock.h"
#include "lwip/udp.h"

namespace rtps {

struct UdpConnection {
  udp_pcb *pcb = nullptr;
  uint16_t port = 0;

  UdpConnection() = default; // Required for static allocation

  explicit UdpConnection(uint16_t port) : port(port) {
    TcpipCoreLock lock;
    pcb = udp_new();
  }

  UdpConnection &operator=(UdpConnection &&other) noexcept {
    port = other.port;

    if (pcb != nullptr) {
      TcpipCoreLock lock;
      udp_remove(pcb);
    }
    pcb = other.pcb;
    other.pcb = nullptr;
    return *this;
  }

  ~UdpConnection() {
    if (pcb != nullptr) {
      TcpipCoreLock lock;
      udp_remove(pcb);
      pcb = nullptr;
    }
  }
};
} // namespace rtps

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>
#include "rtps/common/types.h"
#include "rtps/utils/sysFunctions.h"
#include "rtps/utils/iptypes.h"

// todo: check/remove
#include <sys/types.h>
#include <arpa/inet.h>

#include <string.h>
#include <vector>

namespace rtps {

typedef void (*udpRxFunc_fp)(void *arg, Ip4Port_t destPort, std::vector<uint8_t> &p, 
                               const ip_struct_t *addr, Ip4Port_t port);

struct UdpConnection {
  int socket_fd = -1;
  Ip4Port_t port = 0;
  udpRxFunc_fp m_rxCallback = nullptr;
  void *m_callbackArgs = nullptr;
  Thread recvThread{};

  UdpConnection() = default; // Required for static allocation

  explicit UdpConnection(Ip4Port_t pport, udpRxFunc_fp rxCallback, void *callbackArgs) : 
      port(pport), m_rxCallback(rxCallback), m_callbackArgs(callbackArgs) {
    //TcpipCoreLock lock;
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
      throw std::runtime_error("socket call returned invalid fd");
    }

    // bentodo: logging
    int opt = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
      std::cout << "setsockopt(SO_REUSEADDR) failed" << std::endl;
      close(socket_fd);
      throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");
    }

#if 0
  int loop = 1;
  if (setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
      std::cout << "setsockopt(IP_MULTICAST_LOOP) failed" << std::endl;
  }
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(socket_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
      std::cout << "bind failed: " << strerror(errno) << std::endl;
      close(socket_fd);
      throw std::runtime_error("bind failed");
    }
    
    // copy so that move ctor doesn't mess this up
    auto fd = socket_fd;
    auto rxCallback_copy = m_rxCallback;
    auto callbackArgs_copy = m_callbackArgs;
    auto port_copy = port;
    recvThread = Thread(new std::thread([fd, rxCallback_copy, callbackArgs_copy, port_copy](){
      // bentodo: copy?
      constexpr size_t BUF_SZ = 65535;
      std::vector<uint8_t> buf(BUF_SZ);

      while (true) {
        std::cout << "Start receive loop for fd " << fd << "." << std::endl;
        buf.resize(BUF_SZ);
        sockaddr_in src{};
        socklen_t srclen = sizeof(src);
        ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0,
                            reinterpret_cast<sockaddr*>(&src), &srclen);
        if (n <= 0) {
          if(errno != 0) {
            std::cout << "recvfrom error: " << strerror(errno) << std::endl;
            continue; // bentodo
          }
          if (errno == EINTR) {
            continue;
          }
          break;
        }

        buf.resize(n);

        ip_struct_t src_addr;
        if(src.sin_family == AF_INET) {
          src_addr.u_addr.ip4.addr = ntohl(src.sin_addr.s_addr); // TODO: should ip_struct_t not better always be in network byte order?
          src_addr.type = ip_addr_type_enum::IPADDR_TYPE_V4;
        } else {
          std::cout << "received non-ipv4 message" << std::endl;
          break;
        }
        std::cout << "recv Start callback." << std::endl;
        rxCallback_copy(callbackArgs_copy, port_copy, buf, &src_addr, ntohs(src.sin_port));
        std::cout << "recv Finish callback." << std::endl;
      }
    }));
  }

  UdpConnection(UdpConnection &&other) noexcept : 
      socket_fd(other.socket_fd), port(other.port), m_rxCallback(other.m_rxCallback), m_callbackArgs(other.m_callbackArgs), recvThread(std::move(other.recvThread)) {
    other.socket_fd = -1;
  }
  /*UdpConnection &operator=(UdpConnection &&other) noexcept {
    port = other.port;

    if (socket_fd >= 0) {
      //TcpipCoreLock lock;
      // bentodo: shutdown?
      // bentodo: synchronization?
      close(socket_fd);
    }
    socket_fd = other.socket_fd;
    other.socket_fd = -1;

    // bentodo: thread, callback+args
    return *this;
  }*/

  ~UdpConnection() {
    if (socket_fd >= 0) {
      //TcpipCoreLock lock;
      shutdown(socket_fd, SHUT_RDWR);
      std::cout << "Shutdown socket " << socket_fd << "." << std::endl;
      joinThread(recvThread);
      close(socket_fd);
      std::cout << "Closed socket " << socket_fd << "." << std::endl;
    }
  }
};
} // namespace rtps


#endif

#endif // RTPS_UDPCONNECTION_H
