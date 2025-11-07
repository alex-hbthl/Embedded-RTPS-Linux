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

#include "rtps/communication/UdpDriver.h"
#include "rtps/communication/TcpipCoreLock.h"
#include "rtps/utils/Lock.h"
#include "rtps/utils/Log.h"

using rtps::UdpDriver;

#if UDP_DRIVER_VERBOSE && RTPS_GLOBAL_VERBOSE
#include "rtps/utils/printutils.h"
#define UDP_DRIVER_LOG(...)                                                    \
  if (true) {                                                                  \
    printf("[UDP Driver] ");                                                   \
    printf(__VA_ARGS__);                                                       \
    printf("\n");                                                              \
  }
#else
#define UDP_DRIVER_LOG(...) //
#endif

#ifndef EMBRTPS_USE_SOCKETS

#include <lwip/igmp.h>
#include <lwip/tcpip.h>

UdpDriver::UdpDriver(rtps::UdpDriver::udpRxFunc_fp callback, void *args)
    : m_rxCallback(callback), m_callbackArgs(args) {}

const rtps::UdpConnection *
UdpDriver::createUdpConnection(Ip4Port_t receivePort) {
  for (uint8_t i = 0; i < m_numConns; ++i) {
    if (m_conns[i].port == receivePort) {
      return &m_conns[i];
    }
  }

  if (m_numConns == m_conns.size()) {
    return nullptr;
  }

  UdpConnection udp_conn(receivePort);

  {
    TcpipCoreLock lock;
    err_t err = udp_bind(udp_conn.pcb, IP_ADDR_ANY,
                         receivePort); // to receive multicast

    if (err != ERR_OK && err != ERR_USE) {
      return nullptr;
    }

    udp_recv(udp_conn.pcb, m_rxCallback, m_callbackArgs);
  }

  m_conns[m_numConns] = std::move(udp_conn);
  m_numConns++;

  UDP_DRIVER_LOG("Successfully created UDP connection on port %u \n",
                 receivePort);

  return &m_conns[m_numConns - 1];
}

bool UdpDriver::isSameSubnet(ip4_addr_t addr) {
  return (ip4_addr_netcmp(&addr, &(netif_default->ip_addr),
                          &(netif_default->netmask)) != 0);
}

bool UdpDriver::joinMultiCastGroup(ip4_addr_t addr) const {
  err_t iret;

  {
    TcpipCoreLock lock;
    iret = igmp_joingroup(IP_ADDR_ANY, (&addr));
  }

  if (iret != ERR_OK) {

    UDP_DRIVER_LOG("Failed to join IGMP multicast group %s\n",
                   ipaddr_ntoa(&addr));

    return false;
  } else {

    UDP_DRIVER_LOG("Succesfully joined  IGMP multicast group %s\n",
                   ipaddr_ntoa(&addr));
  }
  return true;
}

bool UdpDriver::sendPacket(const UdpConnection &conn, ip4_addr_t &destAddr,
                           Ip4Port_t destPort, pbuf &buffer) {
  err_t err;
  {
    TcpipCoreLock lock;
    err = udp_sendto(conn.pcb, &buffer, &destAddr, destPort);
  }

  if (err != ERR_OK) {
    ;

    UDP_DRIVER_LOG("UDP TRANSMIT NOT SUCCESSFUL %s:%u size: %u err: %i\n",
                   ipaddr_ntoa(&destAddr), destPort, buffer.tot_len, err);

    return false;
  }
  return true;
}

void UdpDriver::sendPacket(PacketInfo &packet) {
  auto p_conn = createUdpConnection(packet.srcPort);
  if (p_conn == nullptr) {
    ;

    UDP_DRIVER_LOG("Failed to create connection on port %u \n", packet.srcPort);

    return;
  }

  sendPacket(*p_conn, packet.destAddr, packet.destPort,
             *packet.buffer.firstElement);
}

#else

#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

UdpDriver::UdpDriver(rtps::udpRxFunc_fp callback, void *args)
    : m_rxCallback(callback), m_callbackArgs(args) {}

const rtps::UdpConnection *
UdpDriver::createUdpConnection(Ip4Port_t receivePort) {
  for(auto &con : m_conns) {
    if (con.port == receivePort) {
      return &con;
    }
  }

  if (m_conns.size() == Config::MAX_NUM_UDP_CONNECTIONS) {
    return nullptr;
  }

  m_conns.emplace_back(receivePort, m_rxCallback, m_callbackArgs);

  // bentodo: check success
  UDP_DRIVER_LOG("Successfully created UDP connection on port %u \n",
                 receivePort);

  return &m_conns.back();
}

bool UdpDriver::isSameSubnet(ip4_struct_t addr) {
  // bentodo: use ip address from config / iterate through ipv4 network interfaces and check against all
  return (addr.addr & 0x00FFFFFF) == 0x0002A8C0;
}

bool UdpDriver::joinMultiCastGroup(ip4_struct_t addr) const {

  bool success = true;
  
  for(auto &con : m_conns) {
    if (con.socket_fd < 0) {
      continue;
    }

#if 1
    in_addr local_if_addr;
    local_if_addr.s_addr = inet_addr(Config::local_interface_ip);
    if (setsockopt(con.socket_fd, IPPROTO_IP, IP_MULTICAST_IF, &local_if_addr, sizeof(local_if_addr)) < 0) {
      UDP_DRIVER_LOG("setsockopt(IP_MULTICAST_IF) failed");
      success = false;
      // continue trying other sockets
    }
#endif

    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = addr.addr;
    mreq.imr_interface.s_addr = local_if_addr.s_addr; //INADDR_ANY; // let kernel pick the interface

    if (setsockopt(con.socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
      UDP_DRIVER_LOG("Failed to join multicast group %s on fd %d: %s\n",
                     inet_ntoa(*(in_addr*)&addr), con.socket_fd, strerror(errno));
      success = false;
      // continue trying other sockets
    } else {
      UDP_DRIVER_LOG("Successfully joined multicast group %s on fd %d\n",
                     inet_ntoa(*(in_addr*)&addr), con.socket_fd);
    }
  }

  // bentodo: restart receive loop?

  // bentodo: kinda duplicate
  if (!success) {

    UDP_DRIVER_LOG("Failed to join IGMP multicast group %s\n",
                   inet_ntoa(*(in_addr*)&addr));

    return false;
  } else {

    UDP_DRIVER_LOG("Succesfully joined IGMP multicast group %s\n",
                   inet_ntoa(*(in_addr*)&addr));
  }
  return true;
}

bool UdpDriver::sendPacket(const UdpConnection &conn, ip4_struct_t &destAddr,
                           Ip4Port_t destPort, PBufWrapper &buffer) {
  
  if(conn.socket_fd < 0 || buffer.m_buf.empty()) {
    return false;
  }

  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(destPort);
  dst.sin_addr.s_addr = destAddr.addr; // already in network byte order

  std::cout << "Sending packet of length " << buffer.m_buf.size() << " to ip address " << inet_ntoa(*(in_addr*)&destAddr) << std::endl;
  ssize_t sent = sendto(conn.socket_fd,
                        buffer.m_buf.data(),
                        buffer.m_buf.size(), /* todo: unused data in m_buf*/
                        0,
                        reinterpret_cast<const sockaddr*>(&dst),
                        sizeof(dst));
  
  if(sent != static_cast<ssize_t>(buffer.m_buf.size())) {
    UDP_DRIVER_LOG("UDP TRANSMIT NOT SUCCESSFUL %s:%u size: %lu: %s\n",
                   inet_ntoa(*(in_addr*)&destAddr), destPort, buffer.m_buf.size(), strerror(errno));

    return false;
  }
  return true;
}

void UdpDriver::sendPacket(PacketInfo &packet) {
  auto p_conn = createUdpConnection(packet.srcPort);
  if (p_conn == nullptr) {
    UDP_DRIVER_LOG("Failed to create connection on port %u \n", packet.srcPort);

    return;
  }

  sendPacket(*p_conn, packet.destAddr, packet.destPort,
             packet.buffer);
}

#endif
