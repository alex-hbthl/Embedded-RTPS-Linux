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

#ifndef RTPS_LOCK_H
#define RTPS_LOCK_H

#ifndef EMBRTPS_USE_SOCKETS
#include "lwip/sys.h"
#else
#include <mutex>
#endif

namespace rtps {
#ifndef EMBRTPS_USE_SOCKETS
using Mutex = sys_mutex_t;
inline int mutex_valid(Mutex *m) {return sys_mutex_valid(m);}
inline err_t mutex_new(Mutex *m) {return sys_mutex_new(m);}
inline void mutex_free(Mutex *m) {sys_mutex_free(m);}
#else
#define ERR_OK 0
using Mutex = std::mutex;
inline int mutex_valid(Mutex *) {return 0;}
inline int8_t mutex_new(Mutex *) { return 0;}
inline void mutex_free(Mutex *) {}
#endif

class Lock {
public:
#ifndef EMBRTPS_USE_SOCKETS
  explicit Lock(sys_mutex_t &passedMutex) : m_mutex(passedMutex) {
    sys_mutex_lock(&m_mutex);
  };

  ~Lock() { sys_mutex_unlock(&m_mutex); };
private:
  sys_mutex_t &m_mutex;
#else
explicit Lock(std::mutex &passedMutex) : lock(passedMutex) {}
private:
  std::lock_guard<std::mutex> lock;
#endif
};
} // namespace rtps
#endif // RTPS_LOCK_H
