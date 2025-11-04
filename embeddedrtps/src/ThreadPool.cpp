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

#include "rtps/ThreadPool.h"

#ifndef EMBRTPS_USE_SOCKETS
#include "lwip/tcpip.h"
#endif

#include "rtps/entities/Writer.h"
#include "rtps/utils/Log.h"
#include "rtps/utils/udpUtils.h"

#include <iostream>

using rtps::ThreadPool;

#define THREAD_POOL_VERBOSE 1
#if THREAD_POOL_VERBOSE && RTPS_GLOBAL_VERBOSE
#include "rtps/utils/printutils.h"
#define THREAD_POOL_LOG(...)  \
if (true) {                   \
  printf("[ThreadPool] ");    \
  printf(__VA_ARGS__);        \
  printf("\n");               \
}
#else
#define THREAD_POOL_LOG(...) //
#endif

ThreadPool::ThreadPool(receiveJumppad_fp receiveCallback, void *callee)
    : m_receiveJumppad(receiveCallback), m_callee(callee) {

  if (!m_queueOutgoing.init() || !m_queueIncoming.init()) {
    return;
  }
  auto inputErr = m_readerNotificationSem.sem_new(0);
  auto outputErr = m_writerNotificationSem.sem_new(0);

  if (inputErr != 0 || outputErr != 0) {
    THREAD_POOL_LOG("ThreadPool: Failed to create Semaphores.\n");
  }
}

ThreadPool::~ThreadPool() {
  std::cout << "Thread pool dtor, running: " << m_running << std::endl;
  if (m_running) {
    std::cout << "Stopping threads" << std::endl;
    stopThreads();
    rtps::sleep_for(500); 
    std::cout << "Done" << std::endl;
  }

  if (m_readerNotificationSem.sem_valid()) {
    m_readerNotificationSem.sem_free();
  }
  if (m_writerNotificationSem.sem_valid()) {
    m_writerNotificationSem.sem_free();
  }
}

bool ThreadPool::startThreads() {
  if (m_running) {
    return true;
  }

  if(!m_readerNotificationSem.sem_valid() || !m_writerNotificationSem.sem_valid()) {
    return false;
  }

  std::cout << "Start " << m_writers.size() << " reader/writer threads!" << std::endl;
  m_running = true;
  for (auto &thread : m_writers) {
    // TODO ID, err check, waitOnStop
    // bentodo: might have to join if threads already existed
    thread = rtps::createThread("WriterThread", writerThreadFunction, this,
                            Config::THREAD_POOL_WRITER_STACKSIZE,
                            Config::THREAD_POOL_WRITER_PRIO);
  }

  for (auto &thread : m_readers) {
    // TODO ID, err check, waitOnStop
    thread = rtps::createThread("ReaderThread", readerThreadFunction, this,
                            Config::THREAD_POOL_READER_STACKSIZE,
                            Config::THREAD_POOL_READER_PRIO);
  }
  return true;
}

void ThreadPool::stopThreads() {
  m_running = false;
  // This should call all the semaphores for each thread once, so they don't
  // stuck before ended.
  for(auto i = 0u; i < m_writers.size(); ++i) {
    m_writerNotificationSem.sem_signal();
  }
  for(auto i = 0u; i < m_readers.size(); ++i) {
    m_readerNotificationSem.sem_signal();
  }
  for (auto &thread : m_writers) {
    joinThread(thread);
  }
  for (auto &thread : m_readers) {
    joinThread(thread);
  }
  std::cout << "Stop threads: Done waiting for threads" << std::endl;
}

void ThreadPool::clearQueues() {
  m_queueOutgoing.clear();
  m_queueIncoming.clear();
}

bool ThreadPool::addWorkload(Writer *workload) {
  bool res = m_queueOutgoing.moveElementIntoBuffer(std::move(workload));
  if (res) {
    m_writerNotificationSem.sem_signal();
  }

  return res;
}

bool ThreadPool::addNewPacket(PacketInfo &&packet) {
  bool res = m_queueIncoming.moveElementIntoBuffer(std::move(packet));
  if (res) {
    m_readerNotificationSem.sem_signal();
  }
  return res;
}

void ThreadPool::writerThreadFunction(void *arg) {
  auto pool = static_cast<ThreadPool *>(arg);
  if (pool == nullptr) {

    THREAD_POOL_LOG("nullptr passed to writer function\n");

    return;
  }

  pool->doWriterWork();
}

void ThreadPool::doWriterWork() {
  while (m_running) {
    Writer *workload;
    auto isWorkToDo = m_queueOutgoing.moveFirstInto(workload);
    if (!isWorkToDo) {
      m_writerNotificationSem.sem_wait();
      continue;
    }

    workload->progress();
  }
}

#ifndef EMBRTPS_USE_SOCKETS
void ThreadPool::readCallback(void *args, udp_pcb *target, pbuf *pbuf,
                              const ip_addr_t * /*addr*/, Ip4Port_t port) {
  auto &pool = *static_cast<ThreadPool *>(args);

  PacketInfo packet;

  // TODO This is a workaround for chained pbufs caused by hardware limitations,
  // not a general fix
  if (pbuf->next != nullptr) {
    struct pbuf *test = pbuf_alloc(PBUF_RAW, pbuf->tot_len, PBUF_POOL);
    pbuf_copy(test, pbuf);
    pbuf_free(pbuf);
    pbuf = test;
  }

  packet.destAddr = {0}; // not relevant
  packet.destPort = target->local_port;
  packet.srcPort = port;
  packet.buffer = PBufWrapper{pbuf};

  if (!pool.addNewPacket(std::move(packet))) {
    THREAD_POOL_LOG("ThreadPool: dropped packet\n");
  }
}

#else
void ThreadPool::readCallback(void *args, Ip4Port_t destPort, std::vector<uint8_t> &p, const ip_struct_t * /*addr*/, Ip4Port_t port) {
  auto &pool = *static_cast<ThreadPool *>(args);

  PacketInfo packet;

  packet.destAddr = {0}; // not relevant
  packet.destPort = destPort;
  packet.srcPort = port;
  packet.buffer = PBufWrapper{p};

  std::cout << "Inside ThreadPool readCallback; p size: " << p.size() << std::endl;

  if (!pool.addNewPacket(std::move(packet))) {
    std::cout << "AddNewPacket returned false" << std::endl;
    THREAD_POOL_LOG("ThreadPool: dropped packet\n");
  } else {
    std::cout << "AddNewPacket returned true" << std::endl;
  }
}
#endif

void ThreadPool::readerThreadFunction(void *arg) {
  auto pool = static_cast<ThreadPool *>(arg);
  if (pool == nullptr) {

    THREAD_POOL_LOG("nullptr passed to reader function\n");

    return;
  }
  pool->doReaderWork();
}

void ThreadPool::doReaderWork() {

  while (m_running) {
    PacketInfo packet;
    auto isWorkToDo = m_queueIncoming.moveFirstInto(packet);
    if (!isWorkToDo) {
      m_readerNotificationSem.sem_wait();
      continue;
    }

    m_receiveJumppad(m_callee, const_cast<const PacketInfo &>(packet));
  }
}

#undef THREAD_POOL_VERBOSE
