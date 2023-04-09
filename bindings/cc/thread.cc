#include "thread.h"

namespace rt {
namespace thread_internal {

// A helper to jump from a C function to a C++ std::function.
void ThreadTrampoline(void *arg) {
  (*static_cast<std::function<void()>*>(arg))();
}

// A helper to jump from a C function to a C++ std::function. This variant
// can wait for the thread to be joined.
void ThreadTrampolineWithJoin(void *arg)
{
  thread_internal::join_data *d = static_cast<thread_internal::join_data*>(arg);
  d->func_();

  preempt_disable();
  spin_lock(&d->lock_);
  if (d->done_) {
    spin_unlock(&d->lock_);
    if (d->waiter_)
      thread_ready_preempt_disabled(d->waiter_);
    preempt_enable();
    return;
  }
  d->done_ = true;
  d->waiter_ = thread_self();
  thread_park_and_unlock_np(&d->lock_);
}

} // namespace thread_internal

Thread::~Thread() {
  if (unlikely(join_data_ != nullptr)) BUG();
}

Thread::Thread(const std::function<void()>& func)
{
  preempt_disable();
  thread_internal::join_data *buf;
  thread_t *th = thread_create_with_buf(
    thread_internal::ThreadTrampolineWithJoin,
    reinterpret_cast<void**>(&buf), sizeof(*buf));
  if (unlikely(!th)) BUG();
  new(buf) thread_internal::join_data(func);
  join_data_ = buf;
  thread_ready_preempt_disabled(th);
  preempt_enable();
}

Thread::Thread(std::function<void()>&& func)
{
  preempt_disable();
  thread_internal::join_data *buf;
  thread_t *th = thread_create_with_buf(
    thread_internal::ThreadTrampolineWithJoin,
    reinterpret_cast<void**>(&buf), sizeof(*buf));
  if (unlikely(!th)) BUG();
  new(buf) thread_internal::join_data(std::move(func));
  join_data_ = buf;
  thread_ready_preempt_disabled(th);
  preempt_enable();
}

void Thread::Detach()
{
  preempt_disable();
  if (unlikely(join_data_ == nullptr)) BUG();

  spin_lock(&join_data_->lock_);
  if (join_data_->done_) {
    spin_unlock(&join_data_->lock_);
    assert(join_data_->waiter_ != nullptr);
    thread_ready_preempt_disabled(join_data_->waiter_);
    join_data_ = nullptr;
    preempt_enable();
    return;
  }
  join_data_->done_ = true;
  join_data_->waiter_ = nullptr;
  spin_unlock(&join_data_->lock_);
  join_data_ = nullptr;
  preempt_enable();
}

void Thread::Join()
{
  preempt_disable();
  if (unlikely(join_data_ == nullptr)) BUG();

  spin_lock(&join_data_->lock_);
  if (join_data_->done_) {
    spin_unlock(&join_data_->lock_);
    assert(join_data_->waiter_ != nullptr);
    thread_ready_preempt_disabled(join_data_->waiter_);
    join_data_ = nullptr;
    preempt_enable();
    return;
  }
  join_data_->done_ = true;
  join_data_->waiter_ = thread_self();
  thread_park_and_unlock_np(&join_data_->lock_);
  join_data_ = nullptr;
}

} // namespace rt
