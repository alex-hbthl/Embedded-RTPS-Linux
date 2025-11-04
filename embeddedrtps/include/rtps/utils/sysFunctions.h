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

#ifndef PROJECT_SYSFUNCTIONS_H
#define PROJECT_SYSFUNCTIONS_H

#ifndef EMBRTPS_USE_SOCKETS
#include "lwip/sys.h"
#else
#include <chrono>
#include <thread>
#include <memory>
#include <condition_variable>
#include <mutex>
#endif
#include "rtps/common/types.h"

namespace rtps {
inline Time_t getCurrentTimeStamp() {
  Time_t now;
  // TODO FIX
#ifndef EMBRTPS_USE_SOCKETS
  uint32_t nowMs = sys_now();
#else
  using namespace std::chrono;
  uint32_t nowMs = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
#endif
  now.seconds = (int32_t)nowMs / 1000;
  now.fraction = ((nowMs % 1000) / 1000);
  return now;
}

inline void sleep_for(int ms) {
#ifndef EMBRTPS_USE_SOCKETS
  sys_msleep(ms);
#else
  std::this_thread::sleep_for(std::chrono::milliseconds{ms});
#endif
}

#ifdef EMBRTPS_USE_SOCKETS
// From https://stackoverflow.com/a/4793662
// C++20 can use std::binary_semaphore
class SemaphoreImpl {
    std::mutex mutex_{};
    std::condition_variable condition_{};
    unsigned long count_ = 0; // Initialized as locked.

public:
    SemaphoreImpl(uint8_t count = 0) : count_(count) {}
    
    void release() {
        std::lock_guard<decltype(mutex_)> lock(mutex_);
        ++count_;
        condition_.notify_one();
    }

    void acquire() {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        while(!count_) // Handle spurious wake-ups.
            condition_.wait(lock);
        --count_;
    }
};
#endif

struct Semaphore
{
#ifndef EMBRTPS_USE_SOCKETS
  err_t sem_new(uint8_t count) {
    return sys_sem_new(&sem, count);
  }
  void sem_signal() {
    sys_sem_signal(&sem);
  }
  void sem_wait() {
    sys_sem_wait(&sem);
  }
  void sem_free() {
    sys_sem_free(&sem);
  }
  int sem_valid() {
    return sys_sem_valid(&sem);
  }
private:
  sys_sem_t sem;
#else
  int8_t sem_new(uint8_t count) {
    sem = std::unique_ptr<SemaphoreImpl>(new SemaphoreImpl(count));
    return 0;
  }
  void sem_signal() {
    sem->release();
  }
  void sem_wait() {
    sem->acquire();
  }
  void sem_free() {
    sem.reset();
  }
  int sem_valid() {
    return sem != nullptr;
  }
private:
  std::unique_ptr<SemaphoreImpl> sem = nullptr;
#endif
};


#ifndef EMBRTPS_USE_SOCKETS
using Thread = sys_thread_t;
inline Thread createThread(const char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio) {
  return sys_thread_new(name, thread, arg, stacksize, prio);
}
inline void joinThread(Thread &) { /* no-op */ }
#else
struct ThreadJoiner {
    void operator()(std::thread* t) const {
        if (t) {
            if (t->joinable()) {
                auto id = t->get_id();
                std::cout << "Trying to join " << id << "..." << std::endl;
                t->join();
                std::cout << "Successfully joined " << id << "!" << std::endl;
            }
            delete t;
        }
    }
};
using Thread = std::unique_ptr<std::thread, ThreadJoiner>;
typedef void (*thread_fn)(void *arg);
inline Thread createThread(const char *, thread_fn thread, void *arg, int, int) {
  return Thread(new std::thread(thread, arg));
}
inline void joinThread(Thread &t) { if(t) t->join(); }
#endif
} // namespace rtps

#endif // PROJECT_SYSFUNCTIONS_H
