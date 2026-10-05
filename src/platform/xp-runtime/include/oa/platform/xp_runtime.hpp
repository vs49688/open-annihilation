// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

#pragma once

// Slim reader/writer locks, condition variables and one-time initialisation
// built on one pointer-sized word each, as Windows Vista and 7 lay out their
// own. On Windows XP, where the system has none of these, the C++ run-time
// library's calls to them reach these functions instead (see README.md).
// They hold no other state, so a word that is zero is a free lock, a
// condition no thread waits on and an initialisation not yet run, as on
// Windows. A thread that finds a lock busy, or waits on a condition, spins
// briefly, yields its time slice a few times and then sleeps a millisecond
// at a time: adequate for the few short waits the engine has, not for heavy
// contention.

#include <cstdint>

namespace oa::platform::xp_runtime {

/// A timeout that never runs out, in milliseconds.
inline constexpr uint32_t wait_forever = 0xffffffff;

/// Takes a slim lock for the calling thread alone, waiting while any thread holds it.
///
/// @param[in,out] lock the lock's word; zero when free
void lock_exclusive(uintptr_t& lock) noexcept;

/// Takes a slim lock for the calling thread alone when no thread holds it.
///
/// @param[in,out] lock the lock's word
/// @return true when the calling thread now holds the lock
[[nodiscard]] bool try_lock_exclusive(uintptr_t& lock) noexcept;

/// Releases a slim lock the calling thread holds alone.
///
/// @param[in,out] lock the lock's word
void unlock_exclusive(uintptr_t& lock) noexcept;

/// Takes a slim lock shared with other readers, waiting while a thread holds it alone.
///
/// @param[in,out] lock the lock's word
void lock_shared(uintptr_t& lock) noexcept;

/// Releases one reader's share of a slim lock.
///
/// @param[in,out] lock the lock's word
void unlock_shared(uintptr_t& lock) noexcept;

/// The count a condition's word holds now.
///
/// Noted while the lock that guards the condition is still held, so that a
/// wake between noting the count and releasing that lock is not lost.
///
/// @param[in,out] condition the condition's word
/// @return the count, to pass to wait_condition_word
uintptr_t note_condition(uintptr_t& condition) noexcept;

/// Waits until a condition's word holds a count other than the one noted,
/// releasing and taking no lock itself.
///
/// A wait may end without a wake-up, as on Windows; the caller checks its
/// condition again.
///
/// @param[in,out] condition the condition's word
/// @param noted the count note_condition returned
/// @param timeout_ms longest wait in milliseconds, or wait_forever
/// @return false when the time ran out before a wake-up
bool wait_condition_word(uintptr_t& condition, uintptr_t noted, uint32_t timeout_ms) noexcept;

/// Releases a slim lock, waits for the condition to be woken, and takes the lock again.
///
/// A wait may end without a wake-up, as on Windows; the caller checks its
/// condition again.
///
/// @param[in,out] condition the condition's word; zero for a new condition
/// @param[in,out] lock the slim lock the calling thread holds
/// @param timeout_ms longest wait in milliseconds, or wait_forever
/// @param shared true when the calling thread holds the lock shared, false when alone
/// @return false when the time ran out before a wake-up
bool wait_condition(
    uintptr_t& condition, uintptr_t& lock, uint32_t timeout_ms, bool shared
) noexcept;

/// Wakes every thread waiting on a condition.
///
/// Waking one thread wakes them all; each checks its condition again.
///
/// @param[in,out] condition the condition's word
void wake_condition(uintptr_t& condition) noexcept;

/// An initialisation run_once runs.
///
/// @param argument value given to run_once
/// @param[out] result pointer the initialisation hands to later callers, its
///             two low bits clear
/// @return true when the initialisation succeeded
using OnceInitialisation = bool (*)(void* argument, void** result);

/// Runs an initialisation once, however many threads ask at the same time.
///
/// Threads that come while it runs wait for it. When it fails, run_once
/// returns false and the next caller runs it again.
///
/// @param[in,out] once the initialisation's word; zero before it has run
/// @param initialisation function to run
/// @param argument value passed to initialisation
/// @param[out] result the pointer the initialisation handed back; may be null
/// @return true once the initialisation has succeeded
bool run_once(
    uintptr_t& once, OnceInitialisation initialisation, void* argument, void** result
) noexcept;

#if defined(__MINGW32__)
/// Names an open file's path as the final-path call does on Windows Vista and
/// later, from the device path Windows XP has: `\\?\X:\...` for a file on
/// drive X, `\\?\UNC\...` for one in a shared folder on another computer.
/// The path keeps the spelling the file was opened by, short (8.3) names
/// included.
///
/// @param file the open file's handle
/// @param[out] buffer where the path goes; may be null to ask for its size
/// @param capacity size of buffer in characters
/// @param flags the final-path call's flags; the volume may be named as a
///        drive letter (0), by its device (2) or not at all (4)
/// @return the path's length without its terminator when it fits; the size
///         it needs, terminator included, when it does not; 0 with the last
///         error set on failure
uint32_t
final_path_from_device(void* file, wchar_t* buffer, uint32_t capacity, uint32_t flags) noexcept;

/// Reads an open file's information as the by-handle call of Windows Vista
/// and later does, through the native call Windows XP has.
///
/// @param file the open file's handle
/// @param information_class the Windows information class: basic (0),
///        standard (1), name (2), stream (7), compression (8) or attribute
///        tag (9)
/// @param[out] information the record
/// @param length its size in bytes
/// @return true on success; false with the last error set otherwise
bool file_information_from_native(
    void* file, int information_class, void* information, uint32_t length
) noexcept;
#endif

} // namespace oa::platform::xp_runtime
