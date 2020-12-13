#pragma once
#include <utility>
#include <memory>
#include <deque>
#include "net/third_party/quiche/src/quic/platform/api/quic_epoll.h"
#include "net/third_party/quiche/src/quic/core/quic_alarm_factory.h"
#include "base/threading/platform_thread.h"
#include "net/third_party/quiche/src/quic/core/quic_clock.h"
namespace quic{
class QueuedTask {
 public:
  QueuedTask() {}
  virtual ~QueuedTask() {}
  virtual bool Run() = 0;
};
template <class Closure>
class ClosureTask : public QueuedTask {
 public:
  explicit ClosureTask(Closure&& closure)
      : closure_(std::forward<Closure>(closure)) {}
 ~ClosureTask(){ std::cout<<"task dtor"<<std::endl;}
 private:
  bool Run() override {
    closure_();
    return true;
  }

  typename std::remove_const<
      typename std::remove_reference<Closure>::type>::type closure_;
};
template <class Closure, class Cleanup>
class ClosureTaskWithCleanup : public ClosureTask<Closure> {
 public:
  ClosureTaskWithCleanup(Closure&& closure, Cleanup&& cleanup)
      : ClosureTask<Closure>(std::forward<Closure>(closure)),
        cleanup_(std::forward<Cleanup>(cleanup)) {}
  ~ClosureTaskWithCleanup() { cleanup_(); }

 private:
  typename std::remove_const<
      typename std::remove_reference<Cleanup>::type>::type cleanup_;
};

// Convenience function to construct closures that can be passed directly
// to methods that support std::unique_ptr<QueuedTask> but not template
// based parameters.
template <class Closure>
static std::unique_ptr<QueuedTask> NewClosure(Closure&& closure) {
  return std::make_unique<ClosureTask<Closure>>(std::forward<Closure>(closure));
}

template <class Closure, class Cleanup>
static std::unique_ptr<QueuedTask> NewClosure(Closure&& closure,
                                              Cleanup&& cleanup) {
  return std::make_unique<ClosureTaskWithCleanup<Closure, Cleanup>>(
      std::forward<Closure>(closure), std::forward<Cleanup>(cleanup));
}
    
class MyQuicContext{
public:
    virtual ~MyQuicContext(){}
    virtual QuicClock *clock()=0;
    virtual QuicAlarmFactory* alarm_factory() =0;
    virtual QuicEpollServer* epoll_server() =0;
    virtual base::PlatformThreadId context_id() =0;
    template <class Closure,
          typename std::enable_if<!std::is_convertible<
              Closure,
              std::unique_ptr<QueuedTask>>::value>::type* = nullptr>
    void PostTask(Closure&& closure){
        PostInnerTask(NewClosure(std::forward<Closure>(closure)));
    } 
protected:
    virtual void PostInnerTask(std::unique_ptr<QueuedTask> task)=0;
};
}
