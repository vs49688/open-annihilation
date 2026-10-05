// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

#include "oa/platform/xp_runtime.hpp"

#include "oa/base/threads.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <atomic>
#include <chrono>

namespace oa::platform::xp_runtime {
namespace {

/// The lock word's bit for a thread holding it alone.
constexpr uintptr_t exclusive_holder = 1;
/// What each reader adds to the lock word.
constexpr uintptr_t one_reader = 2;

/// The low bits of an initialisation's word that hold its state; the rest
/// holds the result pointer.
constexpr uintptr_t once_state_bits = 3;
constexpr uintptr_t once_not_run = 0;
constexpr uintptr_t once_running = 1;
constexpr uintptr_t once_done = 2;

/// Waits for a busy word this many times on the processor, where a lock held
/// briefly by a thread on another processor is soon free.
constexpr uint32_t spinning_attempts = 64;
/// Then this many more times by yielding the rest of the time slice, before
/// sleeping.
constexpr uint32_t yielding_attempts = spinning_attempts + 16;
/// Sleep between later attempts, in milliseconds.
constexpr uint32_t sleep_between_attempts_ms = 1;

/// Tells the processor that the thread is waiting in a loop, which frees
/// resources for another thread on the same core.
void pause_processor() noexcept {
#if defined(__i386__) || defined(__x86_64__)
    __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("yield");
#endif
}

/// Suspends the calling thread, as oa::base::threads::sleep_ms does.
///
/// On Windows it calls the system itself. A build for Windows XP links this
/// file whole into every program, after the libraries the program names,
/// where oa-base-threads holds the sleep only for a program that sleeps
/// itself.
///
/// @param milliseconds time to sleep; 0 gives up the rest of the time slice
void sleep_for_ms(uint32_t milliseconds) noexcept {
#if defined(_WIN32)
    Sleep(milliseconds);
#else
    base::threads::sleep_ms(milliseconds);
#endif
}

/// Waits a little before a thread looks at a busy word again: first on the
/// processor, then by yielding the rest of its time slice, then by sleeping.
///
/// @param[in,out] attempts how often the caller has waited for this word so far
void back_off(uint32_t& attempts) noexcept {
    if (attempts < spinning_attempts) {
        ++attempts;
        pause_processor();
        return;
    }
    if (attempts < yielding_attempts) {
        ++attempts;
        sleep_for_ms(0);
        return;
    }
    sleep_for_ms(sleep_between_attempts_ms);
}

/// Returns the word as an atomic object.
///
/// @param word a pointer-aligned word
/// @return atomic access to word
std::atomic_ref<uintptr_t> atomic_word(uintptr_t& word) noexcept {
    return std::atomic_ref<uintptr_t>(word);
}

} // namespace

void lock_exclusive(uintptr_t& lock) noexcept {
    uint32_t attempts = 0;
    while (!try_lock_exclusive(lock))
        back_off(attempts);
}

bool try_lock_exclusive(uintptr_t& lock) noexcept {
    uintptr_t free = 0;
    return atomic_word(lock).compare_exchange_strong(
        free, exclusive_holder, std::memory_order_acquire
    );
}

void unlock_exclusive(uintptr_t& lock) noexcept {
    atomic_word(lock).store(0, std::memory_order_release);
}

void lock_shared(uintptr_t& lock) noexcept {
    auto word = atomic_word(lock);
    uint32_t attempts = 0;
    for (;;) {
        uintptr_t seen = word.load(std::memory_order_relaxed);
        if ((seen & exclusive_holder) == 0 &&
            word.compare_exchange_weak(seen, seen + one_reader, std::memory_order_acquire))
            return;
        if ((seen & exclusive_holder) != 0)
            back_off(attempts);
    }
}

void unlock_shared(uintptr_t& lock) noexcept {
    atomic_word(lock).fetch_sub(one_reader, std::memory_order_release);
}

// The condition's word counts wake-ups. A waiter notes the count while it
// still holds the lock, so a wake-up that follows any change the waker made
// under the lock always changes the count the waiter watches.
uintptr_t note_condition(uintptr_t& condition) noexcept {
    return atomic_word(condition).load(std::memory_order_acquire);
}

bool wait_condition_word(uintptr_t& condition, uintptr_t noted, uint32_t timeout_ms) noexcept {
    auto wake_ups = atomic_word(condition);
    const auto started = std::chrono::steady_clock::now();
    uint32_t attempts = 0;
    while (wake_ups.load(std::memory_order_acquire) == noted) {
        if (timeout_ms != wait_forever &&
            std::chrono::steady_clock::now() - started >= std::chrono::milliseconds(timeout_ms))
            return false;
        back_off(attempts);
    }
    return true;
}

bool wait_condition(
    uintptr_t& condition, uintptr_t& lock, uint32_t timeout_ms, bool shared
) noexcept {
    const uintptr_t noted = note_condition(condition);
    if (shared)
        unlock_shared(lock);
    else
        unlock_exclusive(lock);
    const bool woken = wait_condition_word(condition, noted, timeout_ms);
    if (shared)
        lock_shared(lock);
    else
        lock_exclusive(lock);
    return woken;
}

void wake_condition(uintptr_t& condition) noexcept {
    atomic_word(condition).fetch_add(1, std::memory_order_release);
}

bool run_once(
    uintptr_t& once, OnceInitialisation initialisation, void* argument, void** result
) noexcept {
    auto state = atomic_word(once);
    uint32_t attempts = 0;
    for (;;) {
        uintptr_t seen = state.load(std::memory_order_acquire);
        if ((seen & once_state_bits) == once_done) {
            if (result != nullptr)
                *result = reinterpret_cast<void*>(seen & ~once_state_bits);
            return true;
        }
        if (seen == once_not_run &&
            state.compare_exchange_strong(seen, once_running, std::memory_order_acq_rel)) {
            void* handed = nullptr;
            if (!initialisation(argument, &handed)) {
                state.store(once_not_run, std::memory_order_release);
                return false;
            }
            const uintptr_t kept = reinterpret_cast<uintptr_t>(handed) & ~once_state_bits;
            state.store(kept | once_done, std::memory_order_release);
            if (result != nullptr)
                *result = reinterpret_cast<void*>(kept);
            return true;
        }
        back_off(attempts);
    }
}

} // namespace oa::platform::xp_runtime
