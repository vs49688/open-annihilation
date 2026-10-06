// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

// The Windows Vista and 7 functions, and the newer C library functions,
// that the C++ run-time library calls and Windows XP lacks,
// defined under the names a program imports them by. A program linked with
// this file calls these in place of the system's; each uses the system's own
// function when the running Windows has it and a stand-in when it does not.
// Built only for MinGW, whose import naming it follows.

#include "oa/platform/xp_runtime.hpp"

// The C++ standard headers come first, before the Windows XP declarations are
// pinned below: they reach the toolchain's thread support, whose condition
// variables a win32-threaded toolchain declares for the version this file is
// compiled at, not for Windows XP.
#include <atomic>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/utime.h>
#include <cwctype>

// The declarations of Windows XP, so that none of the functions defined here
// is also declared as the system's; and the module list of the process-status
// library, which this file's own module list falls back to.
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#undef WINVER
#define WINVER 0x0501
#undef PSAPI_VERSION
#define PSAPI_VERSION 1
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <psapi.h>

// The symbol a function is defined by, and the import pointer a program
// calls it through, in MinGW's naming: on 32-bit x86 a leading underscore,
// and for the system's functions the size of their arguments.
#if defined(__i386__)
#define OA_XP_SYSTEM_SYMBOL(name, argument_bytes) "_" #name "@" #argument_bytes
#define OA_XP_SYSTEM_IMPORT(name, argument_bytes) "__imp__" #name "@" #argument_bytes
#define OA_XP_LIBRARY_SYMBOL(name) "_" #name
#define OA_XP_LIBRARY_IMPORT(name) "__imp__" #name
#else
#define OA_XP_SYSTEM_SYMBOL(name, argument_bytes) #name
#define OA_XP_SYSTEM_IMPORT(name, argument_bytes) "__imp_" #name
#define OA_XP_LIBRARY_SYMBOL(name) #name
#define OA_XP_LIBRARY_IMPORT(name) "__imp_" #name
#endif

// Defines `function`, declared before with its type, as the system function
// `name` and as the import pointer a program calls `name` through.
#define OA_XP_DEFINE_SYSTEM(function, name, argument_bytes)                                        \
    extern "C" constinit decltype(&function)                                                       \
        const function##_import __asm__(OA_XP_SYSTEM_IMPORT(name, argument_bytes)) = &function
#define OA_XP_DEFINE_LIBRARY(function, name)                                                       \
    extern "C" constinit decltype(&function)                                                       \
        const function##_import __asm__(OA_XP_LIBRARY_IMPORT(name)) = &function

namespace {

namespace xp = oa::platform::xp_runtime;

/// A system function looked up on first use.
///
/// The lookup gives every thread the same answer, so threads that look it
/// up at the same time agree; the result is kept in atomics, which need no
/// code to initialise them.
template <typename Function>
struct SystemFunction {
    const wchar_t* library{};
    const char* name{};
    std::atomic<Function> function{};
    std::atomic<bool> looked_up{};

    /// Returns the function, or null when the running Windows lacks it.
    ///
    /// @return the function the library exports under name
    Function get() noexcept {
        if (!looked_up.load(std::memory_order_acquire)) {
            const HMODULE module = GetModuleHandleW(library);
            Function found = nullptr;
            if (module != nullptr)
                found = reinterpret_cast<Function>(
                    reinterpret_cast<void*>(GetProcAddress(module, name))
                );
            function.store(found, std::memory_order_relaxed);
            looked_up.store(true, std::memory_order_release);
        }
        return function.load(std::memory_order_relaxed);
    }
};

constexpr wchar_t kernel32[] = L"kernel32.dll";
constexpr wchar_t ntdll[] = L"ntdll.dll";

// Slim reader/writer locks and condition variables: the system's when it has
// all of them (Windows 7 and later), the stand-ins otherwise, so that a lock
// is never taken by one and released by the other.
using SlimLockFunction = void(WINAPI*)(void** lock);
using TrySlimLockFunction = BOOLEAN(WINAPI*)(void** lock);
using SleepConditionFunction =
    BOOL(WINAPI*)(void** condition, void** lock, DWORD timeout_ms, ULONG flags);
using WakeConditionFunction = void(WINAPI*)(void** condition);

constinit SystemFunction<SlimLockFunction> system_lock_exclusive{
    kernel32, "AcquireSRWLockExclusive"
};
constinit SystemFunction<SlimLockFunction> system_lock_shared{kernel32, "AcquireSRWLockShared"};
constinit SystemFunction<SlimLockFunction> system_unlock_exclusive{
    kernel32, "ReleaseSRWLockExclusive"
};
constinit SystemFunction<SlimLockFunction> system_unlock_shared{kernel32, "ReleaseSRWLockShared"};
constinit SystemFunction<TrySlimLockFunction> system_try_lock_exclusive{
    kernel32, "TryAcquireSRWLockExclusive"
};
constinit SystemFunction<SleepConditionFunction> system_sleep_condition{
    kernel32, "SleepConditionVariableSRW"
};
constinit SystemFunction<WakeConditionFunction> system_wake_condition{
    kernel32, "WakeConditionVariable"
};
constinit SystemFunction<WakeConditionFunction> system_wake_all_conditions{
    kernel32, "WakeAllConditionVariable"
};

/// Whether the system's slim locks and conditions are used: 0 before the
/// first call decides, 1 for the system's, 2 for the stand-ins.
constinit std::atomic<int32_t> slim_choice{0};
constexpr int32_t slim_undecided = 0;
constexpr int32_t slim_system = 1;
constexpr int32_t slim_stand_in = 2;
/// The flag that marks a condition wait whose lock is held shared.
constexpr ULONG condition_lock_shared = 0x1;

/// Returns true when the running Windows has every slim lock and condition function.
bool system_has_slim_locks() noexcept {
    int32_t choice = slim_choice.load(std::memory_order_acquire);
    if (choice == slim_undecided) {
        const bool all =
            system_lock_exclusive.get() != nullptr && system_lock_shared.get() != nullptr &&
            system_unlock_exclusive.get() != nullptr && system_unlock_shared.get() != nullptr &&
            system_try_lock_exclusive.get() != nullptr && system_sleep_condition.get() != nullptr &&
            system_wake_condition.get() != nullptr && system_wake_all_conditions.get() != nullptr;
        choice = all ? slim_system : slim_stand_in;
        slim_choice.store(choice, std::memory_order_release);
    }
    return choice == slim_system;
}

/// Returns a slim lock's or condition's word.
///
/// @param word the pointer-sized object the caller passed
/// @return the same object as a word
uintptr_t& word_of(void** word) noexcept {
    return *reinterpret_cast<uintptr_t*>(word);
}

// Status codes and information classes of the native file and object calls.
using NtStatus = LONG;

struct IoStatus {
    union {
        NtStatus status;
        void* pointer;
    };

    ULONG_PTR information{};
};

struct CountedString {
    USHORT length{}; ///< bytes
    USHORT capacity{};
    wchar_t* text{};
};

struct ThreadBasicInformation {
    NtStatus exit_status{};
    void* environment_block{};
    HANDLE process_id{};
    HANDLE thread_id{};
    ULONG_PTR affinity_mask{};
    LONG priority{};
    LONG base_priority{};
};

using QueryFileFunction = NtStatus(NTAPI*)(
    HANDLE file, IoStatus* io, void* information, ULONG length, int information_class
);
using QueryObjectFunction = NtStatus(NTAPI*)(
    HANDLE object, int information_class, void* information, ULONG length, ULONG* returned
);
using QueryThreadFunction = NtStatus(NTAPI*)(
    HANDLE thread, int information_class, void* information, ULONG length, ULONG* returned
);
using StatusToErrorFunction = ULONG(NTAPI*)(NtStatus status);

constinit SystemFunction<QueryFileFunction> native_query_file{ntdll, "NtQueryInformationFile"};
constinit SystemFunction<QueryFileFunction> native_set_file{ntdll, "NtSetInformationFile"};
constinit SystemFunction<QueryObjectFunction> native_query_object{ntdll, "NtQueryObject"};
constinit SystemFunction<QueryThreadFunction> native_query_thread{
    ntdll, "NtQueryInformationThread"
};
constinit SystemFunction<StatusToErrorFunction> native_status_to_error{
    ntdll, "RtlNtStatusToDosError"
};

constexpr int object_name_information = 1;
constexpr int thread_basic_information = 0;

/// Sets the thread's last error from a native status code.
///
/// @param status a failed status code
void set_error_from_status(NtStatus status) noexcept {
    const auto to_error = native_status_to_error.get();
    SetLastError(to_error != nullptr ? to_error(status) : ERROR_GEN_FAILURE);
}

/// Pairs a Windows file information class with the native class whose record
/// has the same layout.
struct FileClass {
    int windows_class{};
    int native_class{};
};

// Basic, standard, name, stream, compression and attribute-tag information.
constexpr FileClass file_query_classes[] = {{0, 4}, {1, 5}, {2, 9}, {7, 22}, {8, 28}, {9, 35}};
// Basic, disposition, allocation and end-of-file information.
constexpr FileClass file_set_classes[] = {{0, 4}, {4, 13}, {5, 19}, {6, 20}};

/// Returns the native class of a Windows file information class.
///
/// @param classes the classes the call supports
/// @param windows_class the class the caller asked for
/// @return the native class, or -1 when the stand-in does not support it
template <size_t count>
int native_file_class(const FileClass (&classes)[count], int windows_class) noexcept {
    for (const FileClass& entry : classes)
        if (entry.windows_class == windows_class)
            return entry.native_class;
    return -1;
}

/// Calls a native file information call for a Windows information class.
///
/// @param call the native query or set call; null when the system lacks it
/// @param native_class the native class, or -1 when unsupported
/// @param file the open file
/// @param[in,out] information the record read or written
/// @param length its size in bytes
/// @return TRUE on success; FALSE with the last error set otherwise
BOOL call_file_information(
    QueryFileFunction call, int native_class, HANDLE file, void* information, DWORD length
) noexcept {
    if (call == nullptr || native_class < 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    IoStatus io{};
    const NtStatus status = call(file, &io, information, length, native_class);
    if (status < 0) {
        set_error_from_status(status);
        return FALSE;
    }
    return TRUE;
}

/// Most characters of a file's device path the stand-in reads.
constexpr size_t longest_object_name = 0x8000;
/// Characters of a drive's device name the stand-in reads.
constexpr DWORD longest_device_name = MAX_PATH;
/// The final-path flags that choose how the volume is named.
constexpr DWORD volume_name_mask = 0x7;
constexpr DWORD volume_name_dos = 0x0;
constexpr DWORD volume_name_nt = 0x2;
constexpr DWORD volume_name_none = 0x4;

/// Returns true when `path` starts with `prefix`, compared without case, and
/// the prefix ends at a separator or at the end of the path.
///
/// @param path a device path
/// @param path_length its length in characters
/// @param prefix a device name
/// @param prefix_length its length in characters
bool starts_with_device(
    const wchar_t* path, size_t path_length, const wchar_t* prefix, size_t prefix_length
) noexcept {
    return prefix_length > 0 && path_length >= prefix_length &&
           _wcsnicmp(path, prefix, prefix_length) == 0 &&
           (path_length == prefix_length || path[prefix_length] == L'\\');
}

/// Copies a path into the caller's buffer as the final-path call does.
///
/// @param[out] buffer the caller's buffer
/// @param capacity its size in characters
/// @param head first part of the path
/// @param tail second part of the path
/// @param tail_length the second part's length in characters
/// @return the path's length without its terminator when it fits, or the
///         size it needs with its terminator when it does not
DWORD copy_final_path(
    wchar_t* buffer, DWORD capacity, const wchar_t* head, const wchar_t* tail, size_t tail_length
) noexcept {
    const size_t head_length = std::wcslen(head);
    const size_t length = head_length + tail_length;
    if (buffer == nullptr || length + 1 > capacity)
        return static_cast<DWORD>(length + 1);
    std::memcpy(buffer, head, head_length * sizeof(wchar_t));
    std::memcpy(buffer + head_length, tail, tail_length * sizeof(wchar_t));
    buffer[length] = L'\0';
    return static_cast<DWORD>(length);
}

} // namespace

uint32_t xp::final_path_from_device(
    void* file, wchar_t* buffer, uint32_t capacity, uint32_t flags
) noexcept {
    const auto query_object = native_query_object.get();
    if (query_object == nullptr) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    }
    constexpr size_t name_bytes = sizeof(CountedString) + longest_object_name * sizeof(wchar_t);
    auto* name_record = static_cast<CountedString*>(std::malloc(name_bytes));
    if (name_record == nullptr) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    ULONG returned = 0;
    const NtStatus status = query_object(
        file, object_name_information, name_record, static_cast<ULONG>(name_bytes), &returned
    );
    if (status < 0) {
        std::free(name_record);
        set_error_from_status(status);
        return 0;
    }
    const wchar_t* path = name_record->text;
    const size_t path_length = name_record->length / sizeof(wchar_t);
    DWORD result = 0;
    const DWORD volume = flags & volume_name_mask;
    if (volume == volume_name_nt) {
        result = copy_final_path(buffer, capacity, L"", path, path_length);
    } else if (volume != volume_name_dos && volume != volume_name_none) {
        SetLastError(ERROR_NOT_SUPPORTED);
    } else {
        // Shared folders on other computers: the redirector's device, whose next component may
        // name the drive letter the share is mapped to (";X:...").
        constexpr wchar_t shared_folder_devices[][32] = {
            L"\\Device\\Mup", L"\\Device\\LanmanRedirector"
        };
        bool named = false;
        // A name already in the DOS device form ("\??\X:\..." or
        // "\??\UNC\..."), as some systems give it.
        constexpr wchar_t dos_devices[] = L"\\??\\";
        constexpr size_t dos_devices_length = 4;
        if (path_length > dos_devices_length &&
            std::wcsncmp(path, dos_devices, dos_devices_length) == 0) {
            const wchar_t* head = volume == volume_name_none ? L"" : L"\\\\?\\";
            size_t rest = dos_devices_length;
            if (volume == volume_name_none) {
                while (rest < path_length && path[rest] != L'\\')
                    ++rest;
            }
            result = copy_final_path(buffer, capacity, head, path + rest, path_length - rest);
            named = true;
        }
        for (const wchar_t* device : shared_folder_devices) {
            if (named)
                break;
            const size_t device_length = std::wcslen(device);
            if (!starts_with_device(path, path_length, device, device_length))
                continue;
            size_t rest = device_length;
            if (rest + 1 < path_length && path[rest + 1] == L';') {
                rest = rest + 1;
                while (rest < path_length && path[rest] != L'\\')
                    ++rest;
            }
            const wchar_t* head = volume == volume_name_none ? L"" : L"\\\\?\\UNC";
            result = copy_final_path(buffer, capacity, head, path + rest, path_length - rest);
            named = true;
            break;
        }
        // Local drives: the drive letter whose device the path starts on.
        wchar_t drive[] = L"A:";
        wchar_t device[longest_device_name];
        const DWORD drives = GetLogicalDrives();
        constexpr int drive_letters = 26;
        for (int letter = 0; !named && letter < drive_letters; ++letter) {
            if ((drives & (1u << letter)) == 0)
                continue;
            drive[0] = static_cast<wchar_t>(L'A' + letter);
            if (QueryDosDeviceW(drive, device, longest_device_name) == 0)
                continue;
            const size_t device_length = std::wcslen(device);
            if (!starts_with_device(path, path_length, device, device_length))
                continue;
            wchar_t head[] = L"\\\\?\\A:";
            constexpr size_t head_letter = 4;
            head[head_letter] = drive[0];
            result = copy_final_path(
                buffer,
                capacity,
                volume == volume_name_none ? L"" : head,
                path + device_length,
                path_length - device_length
            );
            named = true;
        }
        if (!named)
            SetLastError(ERROR_PATH_NOT_FOUND);
    }
    std::free(name_record);
    return result;
}

bool xp::file_information_from_native(
    void* file, int information_class, void* information, uint32_t length
) noexcept {
    return call_file_information(
               native_query_file.get(),
               native_file_class(file_query_classes, information_class),
               file,
               information,
               length
           ) != FALSE;
}

// Slim reader/writer locks, condition variables and one-time initialisation.

/// Takes a slim lock for the calling thread alone.
extern "C" void WINAPI
acquire_srw_lock_exclusive(void** lock) __asm__(OA_XP_SYSTEM_SYMBOL(AcquireSRWLockExclusive, 4));

void WINAPI acquire_srw_lock_exclusive(void** lock) {
    if (system_has_slim_locks())
        system_lock_exclusive.get()(lock);
    else
        xp::lock_exclusive(word_of(lock));
}

OA_XP_DEFINE_SYSTEM(acquire_srw_lock_exclusive, AcquireSRWLockExclusive, 4);

/// Takes a slim lock shared with other readers.
extern "C" void WINAPI
acquire_srw_lock_shared(void** lock) __asm__(OA_XP_SYSTEM_SYMBOL(AcquireSRWLockShared, 4));

void WINAPI acquire_srw_lock_shared(void** lock) {
    if (system_has_slim_locks())
        system_lock_shared.get()(lock);
    else
        xp::lock_shared(word_of(lock));
}

OA_XP_DEFINE_SYSTEM(acquire_srw_lock_shared, AcquireSRWLockShared, 4);

/// Releases a slim lock held alone.
extern "C" void WINAPI
release_srw_lock_exclusive(void** lock) __asm__(OA_XP_SYSTEM_SYMBOL(ReleaseSRWLockExclusive, 4));

void WINAPI release_srw_lock_exclusive(void** lock) {
    if (system_has_slim_locks())
        system_unlock_exclusive.get()(lock);
    else
        xp::unlock_exclusive(word_of(lock));
}

OA_XP_DEFINE_SYSTEM(release_srw_lock_exclusive, ReleaseSRWLockExclusive, 4);

/// Releases one reader's share of a slim lock.
extern "C" void WINAPI
release_srw_lock_shared(void** lock) __asm__(OA_XP_SYSTEM_SYMBOL(ReleaseSRWLockShared, 4));

void WINAPI release_srw_lock_shared(void** lock) {
    if (system_has_slim_locks())
        system_unlock_shared.get()(lock);
    else
        xp::unlock_shared(word_of(lock));
}

OA_XP_DEFINE_SYSTEM(release_srw_lock_shared, ReleaseSRWLockShared, 4);

/// Takes a slim lock alone when it is free.
extern "C" BOOLEAN WINAPI try_acquire_srw_lock_exclusive(void** lock) __asm__(
    OA_XP_SYSTEM_SYMBOL(TryAcquireSRWLockExclusive, 4)
);

BOOLEAN WINAPI try_acquire_srw_lock_exclusive(void** lock) {
    if (system_has_slim_locks())
        return system_try_lock_exclusive.get()(lock);
    return xp::try_lock_exclusive(word_of(lock)) ? TRUE : FALSE;
}

OA_XP_DEFINE_SYSTEM(try_acquire_srw_lock_exclusive, TryAcquireSRWLockExclusive, 4);

/// Releases a slim lock, waits on a condition and takes the lock again.
extern "C" BOOL WINAPI sleep_condition_variable_srw(
    void** condition, void** lock, DWORD timeout_ms, ULONG flags
) __asm__(OA_XP_SYSTEM_SYMBOL(SleepConditionVariableSRW, 16));

BOOL WINAPI
sleep_condition_variable_srw(void** condition, void** lock, DWORD timeout_ms, ULONG flags) {
    if (system_has_slim_locks())
        return system_sleep_condition.get()(condition, lock, timeout_ms, flags);
    const uint32_t timeout = timeout_ms == INFINITE ? xp::wait_forever : timeout_ms;
    if (xp::wait_condition(
            word_of(condition), word_of(lock), timeout, (flags & condition_lock_shared) != 0
        ))
        return TRUE;
    SetLastError(ERROR_TIMEOUT);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(sleep_condition_variable_srw, SleepConditionVariableSRW, 16);

/// Wakes a thread waiting on a condition.
extern "C" void WINAPI
wake_condition_variable(void** condition) __asm__(OA_XP_SYSTEM_SYMBOL(WakeConditionVariable, 4));

void WINAPI wake_condition_variable(void** condition) {
    if (system_has_slim_locks())
        system_wake_condition.get()(condition);
    else
        xp::wake_condition(word_of(condition));
}

OA_XP_DEFINE_SYSTEM(wake_condition_variable, WakeConditionVariable, 4);

/// Wakes every thread waiting on a condition.
extern "C" void WINAPI wake_all_condition_variable(void** condition) __asm__(
    OA_XP_SYSTEM_SYMBOL(WakeAllConditionVariable, 4)
);

void WINAPI wake_all_condition_variable(void** condition) {
    if (system_has_slim_locks())
        system_wake_all_conditions.get()(condition);
    else
        xp::wake_condition(word_of(condition));
}

OA_XP_DEFINE_SYSTEM(wake_all_condition_variable, WakeAllConditionVariable, 4);

namespace {
using OnceCallback = BOOL(CALLBACK*)(void** once, void* parameter, void** context);
using RunOnceFunction =
    BOOL(WINAPI*)(void** once, OnceCallback callback, void* parameter, void** context);
constinit SystemFunction<RunOnceFunction> system_run_once{kernel32, "InitOnceExecuteOnce"};

/// A one-time initialisation's callback and what it is called with.
struct OnceCall {
    OnceCallback callback{};
    void** once{};
    void* parameter{};
};

/// Runs a one-time initialisation's callback for run_once.
///
/// @param argument the OnceCall
/// @param[out] result the context the callback hands back
/// @return true when the callback succeeded
bool call_once_callback(void* argument, void** result) {
    const auto& call = *static_cast<OnceCall*>(argument);
    return call.callback(call.once, call.parameter, result) != FALSE;
}
} // namespace

/// Runs a one-time initialisation.
extern "C" BOOL WINAPI init_once_execute_once(
    void** once, OnceCallback callback, void* parameter, void** context
) __asm__(OA_XP_SYSTEM_SYMBOL(InitOnceExecuteOnce, 16));

BOOL WINAPI
init_once_execute_once(void** once, OnceCallback callback, void* parameter, void** context) {
    if (const auto system = system_run_once.get())
        return system(once, callback, parameter, context);
    OnceCall call{callback, once, parameter};
    return xp::run_once(word_of(once), call_once_callback, &call, context) ? TRUE : FALSE;
}

OA_XP_DEFINE_SYSTEM(init_once_execute_once, InitOnceExecuteOnce, 16);

// Fiber-local storage: the system's when it has it; otherwise thread-local
// storage, whose slots are not freed by a callback when a thread ends.

namespace {
using FlsAllocFunction = DWORD(WINAPI*)(void(WINAPI* callback)(void*));
using FlsGetFunction = void*(WINAPI*)(DWORD index);
using FlsSetFunction = BOOL(WINAPI*)(DWORD index, void* value);
constinit SystemFunction<FlsAllocFunction> system_fls_alloc{kernel32, "FlsAlloc"};
constinit SystemFunction<FlsGetFunction> system_fls_get{kernel32, "FlsGetValue"};
constinit SystemFunction<FlsSetFunction> system_fls_set{kernel32, "FlsSetValue"};

/// Returns true when the running Windows has fiber-local storage.
bool system_has_fiber_storage() noexcept {
    return system_fls_alloc.get() != nullptr && system_fls_get.get() != nullptr &&
           system_fls_set.get() != nullptr;
}
} // namespace

/// Allocates a fiber-local storage slot.
extern "C" DWORD WINAPI
fls_alloc(void(WINAPI* callback)(void*)) __asm__(OA_XP_SYSTEM_SYMBOL(FlsAlloc, 4));

DWORD WINAPI fls_alloc(void(WINAPI* callback)(void*)) {
    if (system_has_fiber_storage())
        return system_fls_alloc.get()(callback);
    return TlsAlloc();
}

OA_XP_DEFINE_SYSTEM(fls_alloc, FlsAlloc, 4);

/// Reads a fiber-local storage slot.
extern "C" void* WINAPI fls_get_value(DWORD index) __asm__(OA_XP_SYSTEM_SYMBOL(FlsGetValue, 4));

void* WINAPI fls_get_value(DWORD index) {
    if (system_has_fiber_storage())
        return system_fls_get.get()(index);
    return TlsGetValue(index);
}

OA_XP_DEFINE_SYSTEM(fls_get_value, FlsGetValue, 4);

/// Writes a fiber-local storage slot.
extern "C" BOOL WINAPI
fls_set_value(DWORD index, void* value) __asm__(OA_XP_SYSTEM_SYMBOL(FlsSetValue, 8));

BOOL WINAPI fls_set_value(DWORD index, void* value) {
    if (system_has_fiber_storage())
        return system_fls_set.get()(index, value);
    return TlsSetValue(index, value);
}

OA_XP_DEFINE_SYSTEM(fls_set_value, FlsSetValue, 8);

// Threads, processors, locales and modules.

namespace {
using ThreadIdFunction = DWORD(WINAPI*)(HANDLE thread);
using ProcessorCountFunction = DWORD(WINAPI*)(WORD group);
using LocaleInfoFunction =
    int(WINAPI*)(const wchar_t* locale, LCTYPE type, wchar_t* data, int capacity);
using EnumModulesFunction =
    BOOL(WINAPI*)(HANDLE process, HMODULE* modules, DWORD bytes, DWORD* needed);
constinit SystemFunction<ThreadIdFunction> system_thread_id{kernel32, "GetThreadId"};
constinit SystemFunction<ProcessorCountFunction> system_processor_count{
    kernel32, "GetActiveProcessorCount"
};
constinit SystemFunction<LocaleInfoFunction> system_locale_info{kernel32, "GetLocaleInfoEx"};
constinit SystemFunction<EnumModulesFunction> system_enum_modules{
    kernel32, "K32EnumProcessModules"
};

/// The locale identifiers of the locale names a program can give without
/// knowing the system's locales: the invariant locale, and the system's.
constexpr LCID invariant_locale = 0x007f;
constexpr wchar_t system_default_locale_name[] = L"!x-sys-default-locale";
} // namespace

/// Returns a thread's identifier from its handle.
extern "C" DWORD WINAPI get_thread_id(HANDLE thread) __asm__(OA_XP_SYSTEM_SYMBOL(GetThreadId, 4));

DWORD WINAPI get_thread_id(HANDLE thread) {
    if (const auto system = system_thread_id.get())
        return system(thread);
    const auto query_thread = native_query_thread.get();
    ThreadBasicInformation information{};
    if (query_thread == nullptr) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    }
    const NtStatus status =
        query_thread(thread, thread_basic_information, &information, sizeof(information), nullptr);
    if (status < 0) {
        set_error_from_status(status);
        return 0;
    }
    return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(information.thread_id));
}

OA_XP_DEFINE_SYSTEM(get_thread_id, GetThreadId, 4);

/// Returns how many logical processors the system has.
extern "C" DWORD WINAPI
get_active_processor_count(WORD group) __asm__(OA_XP_SYSTEM_SYMBOL(GetActiveProcessorCount, 4));

DWORD WINAPI get_active_processor_count(WORD group) {
    if (const auto system = system_processor_count.get())
        return system(group);
    SYSTEM_INFO information{};
    GetSystemInfo(&information);
    return information.dwNumberOfProcessors;
}

OA_XP_DEFINE_SYSTEM(get_active_processor_count, GetActiveProcessorCount, 4);

/// Reads a locale's information by the locale's name.
///
/// Without the system's call it knows the user's locale (a null name), the
/// invariant locale (an empty name) and the system's locale, and fails with
/// ERROR_INVALID_PARAMETER for any other name.
extern "C" int WINAPI get_locale_info_ex(
    const wchar_t* locale, LCTYPE type, wchar_t* data, int capacity
) __asm__(OA_XP_SYSTEM_SYMBOL(GetLocaleInfoEx, 16));

int WINAPI get_locale_info_ex(const wchar_t* locale, LCTYPE type, wchar_t* data, int capacity) {
    if (const auto system = system_locale_info.get())
        return system(locale, type, data, capacity);
    LCID identifier = LOCALE_USER_DEFAULT;
    if (locale != nullptr && locale[0] == L'\0')
        identifier = invariant_locale;
    else if (locale != nullptr && std::wcscmp(locale, system_default_locale_name) == 0)
        identifier = LOCALE_SYSTEM_DEFAULT;
    else if (locale != nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    return GetLocaleInfoW(identifier, type, data, capacity);
}

OA_XP_DEFINE_SYSTEM(get_locale_info_ex, GetLocaleInfoEx, 16);

/// Lists the modules a process has loaded.
extern "C" BOOL WINAPI enum_process_modules(
    HANDLE process, HMODULE* modules, DWORD bytes, DWORD* needed
) __asm__(OA_XP_SYSTEM_SYMBOL(K32EnumProcessModules, 16));

BOOL WINAPI enum_process_modules(HANDLE process, HMODULE* modules, DWORD bytes, DWORD* needed) {
    if (const auto system = system_enum_modules.get())
        return system(process, modules, bytes, needed);
    return EnumProcessModules(process, modules, bytes, needed);
}

OA_XP_DEFINE_SYSTEM(enum_process_modules, K32EnumProcessModules, 16);

// Files.

namespace {
using FileInformationFunction =
    BOOL(WINAPI*)(HANDLE file, int information_class, void* information, DWORD length);
using FinalPathFunction = DWORD(WINAPI*)(HANDLE file, wchar_t* path, DWORD capacity, DWORD flags);
using SymbolicLinkFunction =
    BOOLEAN(WINAPI*)(const wchar_t* link, const wchar_t* target, DWORD flags);
constinit SystemFunction<FileInformationFunction> system_get_file_information{
    kernel32, "GetFileInformationByHandleEx"
};
constinit SystemFunction<FileInformationFunction> system_set_file_information{
    kernel32, "SetFileInformationByHandle"
};
constinit SystemFunction<FinalPathFunction> system_final_path{
    kernel32, "GetFinalPathNameByHandleW"
};
constinit SystemFunction<SymbolicLinkFunction> system_symbolic_link{
    kernel32, "CreateSymbolicLinkW"
};
} // namespace

/// Reads an open file's information.
///
/// Without the system's call it reads the basic, standard, name, stream,
/// compression and attribute-tag records, whose layouts the native calls
/// share.
extern "C" BOOL WINAPI get_file_information_by_handle_ex(
    HANDLE file, int information_class, void* information, DWORD length
) __asm__(OA_XP_SYSTEM_SYMBOL(GetFileInformationByHandleEx, 16));

BOOL WINAPI get_file_information_by_handle_ex(
    HANDLE file, int information_class, void* information, DWORD length
) {
    if (const auto system = system_get_file_information.get())
        return system(file, information_class, information, length);
    return xp::file_information_from_native(file, information_class, information, length) ? TRUE
                                                                                          : FALSE;
}

OA_XP_DEFINE_SYSTEM(get_file_information_by_handle_ex, GetFileInformationByHandleEx, 16);

/// Changes an open file's information.
///
/// Without the system's call it writes the basic, disposition, allocation and
/// end-of-file records.
extern "C" BOOL WINAPI set_file_information_by_handle(
    HANDLE file, int information_class, void* information, DWORD length
) __asm__(OA_XP_SYSTEM_SYMBOL(SetFileInformationByHandle, 16));

BOOL WINAPI set_file_information_by_handle(
    HANDLE file, int information_class, void* information, DWORD length
) {
    if (const auto system = system_set_file_information.get())
        return system(file, information_class, information, length);
    return call_file_information(
        native_set_file.get(),
        native_file_class(file_set_classes, information_class),
        file,
        information,
        length
    );
}

OA_XP_DEFINE_SYSTEM(set_file_information_by_handle, SetFileInformationByHandle, 16);

/// Names an open file's full path.
extern "C" DWORD WINAPI get_final_path_name_by_handle(
    HANDLE file, wchar_t* path, DWORD capacity, DWORD flags
) __asm__(OA_XP_SYSTEM_SYMBOL(GetFinalPathNameByHandleW, 16));

DWORD WINAPI
get_final_path_name_by_handle(HANDLE file, wchar_t* path, DWORD capacity, DWORD flags) {
    if (const auto system = system_final_path.get())
        return system(file, path, capacity, flags);
    return xp::final_path_from_device(file, path, capacity, flags);
}

OA_XP_DEFINE_SYSTEM(get_final_path_name_by_handle, GetFinalPathNameByHandleW, 16);

/// Makes a symbolic link; systems without them fail with ERROR_NOT_SUPPORTED.
extern "C" BOOLEAN WINAPI create_symbolic_link(
    const wchar_t* link, const wchar_t* target, DWORD flags
) __asm__(OA_XP_SYSTEM_SYMBOL(CreateSymbolicLinkW, 12));

BOOLEAN WINAPI create_symbolic_link(const wchar_t* link, const wchar_t* target, DWORD flags) {
    if (const auto system = system_symbolic_link.get())
        return system(link, target, flags);
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(create_symbolic_link, CreateSymbolicLinkW, 12);

// C library functions that take a locale. The engine runs in the
// "C" locale throughout, so each uses the thread's current locale.

/// Tests a wide character's class.
extern "C" int __cdecl
class_alpha(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswalpha_l));

int __cdecl class_alpha(wint_t character, void*) {
    return std::iswalpha(character);
}

OA_XP_DEFINE_LIBRARY(class_alpha, _iswalpha_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_control(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswcntrl_l));

int __cdecl class_control(wint_t character, void*) {
    return std::iswcntrl(character);
}

OA_XP_DEFINE_LIBRARY(class_control, _iswcntrl_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_digit(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswdigit_l));

int __cdecl class_digit(wint_t character, void*) {
    return std::iswdigit(character);
}

OA_XP_DEFINE_LIBRARY(class_digit, _iswdigit_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_lower(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswlower_l));

int __cdecl class_lower(wint_t character, void*) {
    return std::iswlower(character);
}

OA_XP_DEFINE_LIBRARY(class_lower, _iswlower_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_print(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswprint_l));

int __cdecl class_print(wint_t character, void*) {
    return std::iswprint(character);
}

OA_XP_DEFINE_LIBRARY(class_print, _iswprint_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_punctuation(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswpunct_l));

int __cdecl class_punctuation(wint_t character, void*) {
    return std::iswpunct(character);
}

OA_XP_DEFINE_LIBRARY(class_punctuation, _iswpunct_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_space(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswspace_l));

int __cdecl class_space(wint_t character, void*) {
    return std::iswspace(character);
}

OA_XP_DEFINE_LIBRARY(class_space, _iswspace_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_upper(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswupper_l));

int __cdecl class_upper(wint_t character, void*) {
    return std::iswupper(character);
}

OA_XP_DEFINE_LIBRARY(class_upper, _iswupper_l);

/// Tests a wide character's class.
extern "C" int __cdecl
class_hex_digit(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_iswxdigit_l));

int __cdecl class_hex_digit(wint_t character, void*) {
    return std::iswxdigit(character);
}

OA_XP_DEFINE_LIBRARY(class_hex_digit, _iswxdigit_l);

/// Converts a multibyte character to a wide character.
extern "C" int __cdecl multibyte_to_wide(
    wchar_t* wide, const char* text, size_t length, void*
) __asm__(OA_XP_LIBRARY_SYMBOL(_mbtowc_l));

int __cdecl multibyte_to_wide(wchar_t* wide, const char* text, size_t length, void*) {
    return std::mbtowc(wide, text, length);
}

OA_XP_DEFINE_LIBRARY(multibyte_to_wide, _mbtowc_l);

/// Compares two strings by the locale's collation.
extern "C" int __cdecl
collate(const char* left, const char* right, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_strcoll_l));

int __cdecl collate(const char* left, const char* right, void*) {
    return std::strcoll(left, right);
}

OA_XP_DEFINE_LIBRARY(collate, _strcoll_l);

/// Reads a floating-point number from text.
extern "C" double __cdecl
text_to_double(const char* text, char** end, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_strtod_l));

double __cdecl text_to_double(const char* text, char** end, void*) {
    return std::strtod(text, end);
}

OA_XP_DEFINE_LIBRARY(text_to_double, _strtod_l);

/// Transforms a string for comparison by the locale's collation.
extern "C" size_t __cdecl collation_key(
    char* key, const char* text, size_t capacity, void*
) __asm__(OA_XP_LIBRARY_SYMBOL(_strxfrm_l));

size_t __cdecl collation_key(char* key, const char* text, size_t capacity, void*) {
    return std::strxfrm(key, text, capacity);
}

OA_XP_DEFINE_LIBRARY(collation_key, _strxfrm_l);

/// Converts a character to lower case.
extern "C" int __cdecl to_lower(int character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_tolower_l));

int __cdecl to_lower(int character, void*) {
    return std::tolower(character);
}

OA_XP_DEFINE_LIBRARY(to_lower, _tolower_l);

/// Converts a character to upper case.
extern "C" int __cdecl to_upper(int character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_toupper_l));

int __cdecl to_upper(int character, void*) {
    return std::toupper(character);
}

OA_XP_DEFINE_LIBRARY(to_upper, _toupper_l);

/// Converts a wide character to lower case.
extern "C" wint_t __cdecl
wide_to_lower(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_towlower_l));

wint_t __cdecl wide_to_lower(wint_t character, void*) {
    return std::towlower(character);
}

OA_XP_DEFINE_LIBRARY(wide_to_lower, _towlower_l);

/// Converts a wide character to upper case.
extern "C" wint_t __cdecl
wide_to_upper(wint_t character, void*) __asm__(OA_XP_LIBRARY_SYMBOL(_towupper_l));

wint_t __cdecl wide_to_upper(wint_t character, void*) {
    return std::towupper(character);
}

OA_XP_DEFINE_LIBRARY(wide_to_upper, _towupper_l);

/// Compares two wide strings by the locale's collation.
extern "C" int __cdecl wide_collate(const wchar_t* left, const wchar_t* right, void*) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wcscoll_l)
);

int __cdecl wide_collate(const wchar_t* left, const wchar_t* right, void*) {
    return std::wcscoll(left, right);
}

OA_XP_DEFINE_LIBRARY(wide_collate, _wcscoll_l);

/// Transforms a wide string for comparison by the locale's collation.
extern "C" size_t __cdecl wide_collation_key(
    wchar_t* key, const wchar_t* text, size_t capacity, void*
) __asm__(OA_XP_LIBRARY_SYMBOL(_wcsxfrm_l));

size_t __cdecl wide_collation_key(wchar_t* key, const wchar_t* text, size_t capacity, void*) {
    return std::wcsxfrm(key, text, capacity);
}

OA_XP_DEFINE_LIBRARY(wide_collation_key, _wcsxfrm_l);

/// Converts a wide character to a multibyte character, checking the buffer's size.
///
/// @return 0, EILSEQ for a character the locale cannot write, or ERANGE when
///         the buffer is too small
extern "C" errno_t __cdecl wide_to_multibyte_checked(
    size_t* written, char* text, size_t capacity, wchar_t wide, mbstate_t* state
) __asm__(OA_XP_LIBRARY_SYMBOL(wcrtomb_s));

errno_t __cdecl wide_to_multibyte_checked(
    size_t* written, char* text, size_t capacity, wchar_t wide, mbstate_t* state
) {
    char converted[MB_LEN_MAX]{};
    const size_t length = std::wcrtomb(converted, wide, state);
    if (length == static_cast<size_t>(-1)) {
        if (written != nullptr)
            *written = length;
        return EILSEQ;
    }
    if (text != nullptr) {
        if (length > capacity)
            return ERANGE;
        std::memcpy(text, converted, length);
    }
    if (written != nullptr)
        *written = length;
    return 0;
}

OA_XP_DEFINE_LIBRARY(wide_to_multibyte_checked, wcrtomb_s);

/// Sets an environment variable, or removes it when the value is empty.
///
/// @return 0, EINVAL for a missing or malformed name, or ENOMEM
extern "C" errno_t __cdecl put_environment_variable(const char* name, const char* value) __asm__(
    OA_XP_LIBRARY_SYMBOL(_putenv_s)
);

errno_t __cdecl put_environment_variable(const char* name, const char* value) {
    if (name == nullptr || value == nullptr || name[0] == '\0' || std::strchr(name, '=') != nullptr)
        return EINVAL;
    const size_t name_length = std::strlen(name);
    const size_t value_length = std::strlen(value);
    // "name=value": the C library keeps its own copy.
    auto* assignment = static_cast<char*>(std::malloc(name_length + value_length + 2));
    if (assignment == nullptr)
        return ENOMEM;
    std::memcpy(assignment, name, name_length);
    assignment[name_length] = '=';
    std::memcpy(assignment + name_length + 1, value, value_length + 1);
    const int result = _putenv(assignment);
    std::free(assignment);
    return result == 0 ? 0 : EINVAL;
}

OA_XP_DEFINE_LIBRARY(put_environment_variable, _putenv_s);

extern "C" errno_t __cdecl local_time_32(struct tm* out, const __time32_t* timer) __asm__(
    OA_XP_LIBRARY_SYMBOL(_localtime32_s)
);

/// Breaks a 32-bit time down into the local time it names, as _localtime32_s
/// does. The stand-in has the system's localtime fill it in; the C library
/// Windows 95 ships has no secure form of its own.
///
/// @param[out] out receives the broken-down time
/// @param timer seconds since the epoch
/// @return 0, or EINVAL for a null argument or a time localtime refuses
errno_t __cdecl local_time_32(struct tm* out, const __time32_t* timer) {
    if (out == nullptr || timer == nullptr)
        return EINVAL;
    const time_t value = static_cast<time_t>(*timer);
    const struct tm* broken_down = std::localtime(&value);
    if (broken_down == nullptr)
        return EINVAL;
    *out = *broken_down;
    return 0;
}

OA_XP_DEFINE_LIBRARY(local_time_32, _localtime32_s);

// The header names the wide stat calls as macros pointing at a time_t
// variant, and the symbols below are taken from the names as written.
#undef _wstat64
#undef _wstat

extern "C" int __cdecl wide_stat_64(const wchar_t* path, struct _stat64* buffer) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wstat64)
);

/// Stats a path, as _wstat64 does, through the narrow _stat64 the C library
/// Windows 95 ships answers correctly.
///
/// Windows 95's _wstat64 reports every path as absent — a file that is there
/// and a directory that is there alike answer -1 — while its narrow _stat64
/// answers correctly, down to the _S_IFDIR bit and the size. The C++
/// run-time library's std::filesystem stats through _wstat64, so on that
/// system is_directory and exists are false for a directory that is there,
/// and a program asking whether its game folder exists is told it does not.
/// Narrowing the path and asking _stat64 is the whole of the difference: the
/// two agree on the layout of the structure.
///
/// @param path the path to stat
/// @param[out] buffer receives what is known about the path
/// @return 0, or -1 with errno set as _stat64 sets it
int __cdecl wide_stat_64(const wchar_t* path, struct _stat64* buffer) {
    if (path == nullptr || buffer == nullptr) {
        errno = EINVAL;
        return -1;
    }
    char narrow[1024]{};
    const int written = WideCharToMultiByte(
        CP_ACP, 0, path, -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr
    );
    if (written <= 0) {
        errno = ENOENT;
        return -1;
    }
    return _stat64(narrow, buffer);
}

OA_XP_DEFINE_LIBRARY(wide_stat_64, _wstat64);

/// Widens what a narrow search found into the wide structure the wide calls
/// answer with. The two structures hold the same fields in the same order and
/// differ only in the character set of the name, so everything but the name is
/// copied across and the name is widened over.
///
/// @param[out] wide receives the widened match
/// @param narrow what the narrow call found
void wide_find_data(struct _wfinddata_t* wide, const struct _finddata_t& narrow) {
    wide->attrib = narrow.attrib;
    wide->time_create = narrow.time_create;
    wide->time_access = narrow.time_access;
    wide->time_write = narrow.time_write;
    wide->size = narrow.size;
    MultiByteToWideChar(CP_ACP, 0, narrow.name, -1, wide->name, MAX_PATH);
}

// Named as the header names them, for the same reason as the stat calls above.
#undef _wfindfirst32
#undef _wfindnext32
#undef _wfindfirst
#undef _wfindnext

extern "C" long __cdecl wide_find_first(const wchar_t* pattern, struct _wfinddata_t* data) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wfindfirst32)
);

/// Begins a search, as _wfindfirst does, through the narrow _findfirst the C
/// library Windows 95 ships answers correctly.
///
/// Windows 95's _wfindfirst fails with EINVAL for every pattern, so the C++
/// run-time library's directory_iterator — which lists a folder through it —
/// reports "Invalid argument" and a program reading a folder is told the
/// folder cannot be listed even though it is there and its entries are
/// reachable through the narrow call. The search handle the narrow call gives
/// back is used unchanged by _wfindnext below, which is why the two are
/// stood in for together.
///
/// @param pattern the search pattern, as the wide call takes it
/// @param[out] data receives the first match, widened
/// @return a search handle, or -1 with errno set as _findfirst sets it
long __cdecl wide_find_first(const wchar_t* pattern, struct _wfinddata_t* data) {
    if (pattern == nullptr || data == nullptr) {
        errno = EINVAL;
        return -1;
    }
    char narrow[1024]{};
    if (WideCharToMultiByte(
            CP_ACP, 0, pattern, -1, narrow, static_cast<int>(sizeof(narrow)), nullptr, nullptr
        ) <= 0) {
        errno = EINVAL;
        return -1;
    }
    struct _finddata_t found {};
    const long handle = _findfirst(narrow, &found);
    if (handle == -1) {
        if (errno == ENOENT)
            SetLastError(ERROR_FILE_NOT_FOUND);
        return -1;
    }
    wide_find_data(data, found);
    return handle;
}

OA_XP_DEFINE_LIBRARY(wide_find_first, _wfindfirst32);

extern "C" int __cdecl wide_find_next(long handle, struct _wfinddata_t* data) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wfindnext32)
);

/// Continues a search, as _wfindnext does, through the narrow _findnext, on
/// the handle the stand-in above gave back.
///
/// The Windows error is set alongside errno when the search runs out, because
/// the C++ run-time library's directory stream tells the end of a listing from
/// a failure by reading it: the narrow call reports the end through errno
/// alone, so without this a folder read to its last entry is reported as one
/// that cannot be read, and a program listing its game folder is told the
/// folder does not exist.
///
/// @param handle a handle from _wfindfirst
/// @param[out] data receives the next match, widened
/// @return 0 when another was found, -1 with errno set as _findnext sets it
int __cdecl wide_find_next(long handle, struct _wfinddata_t* data) {
    if (data == nullptr) {
        errno = EINVAL;
        return -1;
    }
    struct _finddata_t found {};
    if (_findnext(handle, &found) != 0) {
        if (errno == ENOENT)
            SetLastError(ERROR_NO_MORE_FILES);
        return -1;
    }
    wide_find_data(data, found);
    return 0;
}

OA_XP_DEFINE_LIBRARY(wide_find_next, _wfindnext32);

/// Narrows a path into the buffer a narrow call is given.
///
/// @param[out] narrow receives the path in the system's own character set
/// @param capacity bytes narrow holds
/// @param wide the path to narrow
/// @return true when the system wrote it and it fitted
bool narrow_path(char* narrow, size_t capacity, const wchar_t* wide) noexcept {
    if (narrow == nullptr || wide == nullptr)
        return false;
    return WideCharToMultiByte(
               CP_ACP, 0, wide, -1, narrow, static_cast<int>(capacity), nullptr, nullptr
           ) > 0;
}

// The header names the wide opens beside the narrow ones they are built from.
#undef _wopen
#undef _wfopen
#undef _wfreopen

extern "C" int __cdecl wide_open(const wchar_t* path, int flags, ...) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wopen)
);

/// Opens a file, as _wopen does, through the narrow _open the C library
/// Windows 95 ships answers correctly.
///
/// Windows 95's _wopen fails with EBADF for every path — one that is there and
/// one that is not alike — while its narrow _open opens the same file. The C++
/// run-time library opens every file through it, so on that system no archive
/// of the game's can be opened, and a program reading its game data is told
/// each archive cannot be opened while the files sit there readable.
///
/// The sharing mode is only passed on when it was given: _open takes it with
/// _O_CREAT and not otherwise.
///
/// @param path the file to open
/// @param flags the open flags, as _open takes them
/// @param ... the sharing mode, which _open takes only with _O_CREAT
/// @return the file descriptor, or -1 with errno set as _open sets it
int __cdecl wide_open(const wchar_t* path, int flags, ...) {
    char narrow[1024]{};
    if (!narrow_path(narrow, sizeof(narrow), path)) {
        errno = ENOENT;
        return -1;
    }
    if ((flags & _O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        const int permissions = va_arg(arguments, int);
        va_end(arguments);
        return _open(narrow, flags, permissions);
    }
    return _open(narrow, flags);
}

OA_XP_DEFINE_LIBRARY(wide_open, _wopen);

extern "C" FILE* __cdecl wide_fopen(const wchar_t* path, const wchar_t* mode) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wfopen)
);

/// Opens a stream on a file, as _wfopen does, through the narrow fopen, for the
/// same reason as the wide open above: the wide one is a stub here and the
/// narrow one is not.
///
/// @param path the file to open
/// @param mode the mode to open it with, widened by the caller
/// @return the stream, or null with errno set as fopen sets it
FILE* __cdecl wide_fopen(const wchar_t* path, const wchar_t* mode) {
    char narrow[1024]{};
    char narrow_mode[16]{};
    if (!narrow_path(narrow, sizeof(narrow), path) ||
        !narrow_path(narrow_mode, sizeof(narrow_mode), mode)) {
        errno = ENOENT;
        return nullptr;
    }
    return std::fopen(narrow, narrow_mode);
}

OA_XP_DEFINE_LIBRARY(wide_fopen, _wfopen);

extern "C" FILE* __cdecl wide_freopen(const wchar_t* path, const wchar_t* mode, FILE* stream)
    __asm__(OA_XP_LIBRARY_SYMBOL(_wfreopen));

/// Reopens a stream on another file, as _wfreopen does, through the narrow
/// freopen, for the same reason again.
///
/// @param path the file to open the stream on
/// @param mode the mode to open it with
/// @param stream the stream to reopen
/// @return the stream, or null with errno set as freopen sets it
FILE* __cdecl wide_freopen(const wchar_t* path, const wchar_t* mode, FILE* stream) {
    char narrow[1024]{};
    char narrow_mode[16]{};
    if (!narrow_path(narrow, sizeof(narrow), path) ||
        !narrow_path(narrow_mode, sizeof(narrow_mode), mode)) {
        errno = EINVAL;
        return nullptr;
    }
    return std::freopen(narrow, narrow_mode, stream);
}

OA_XP_DEFINE_LIBRARY(wide_freopen, _wfreopen);

// The wide directory and timestamp calls, which Windows 95 refuses outright.
// Its narrow twins answer, so each of these narrows the path and asks the
// narrow one, as the wide open and the wide stat above do. The header names
// the wide beside the narrow they are built from.
#undef _wmkdir
#undef _wchdir
#undef _wchmod
#undef _wgetcwd
#undef _wutime

extern "C" int __cdecl wide_mkdir(const wchar_t* path) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wmkdir)
);

/// Makes a directory, as _wmkdir does, through the narrow _mkdir the C library
/// Windows 95 ships answers correctly.
///
/// Windows 95's wide directory calls answer -1 with errno EINVAL for every
/// path — a directory to make in a folder right there, and a folder that is
/// already there, alike — while their narrow twins answer as they should. The
/// C++ run-time library makes every directory through _wmkdir, so on that
/// system std::filesystem::create_directories throws "cannot create
/// directories: Invalid argument" and a program that lays down its own folder
/// tree cannot start. Narrowing the path is the whole of the difference.
///
/// @param path the directory to make
/// @return 0, or -1 with errno set as _mkdir sets it
int __cdecl wide_mkdir(const wchar_t* path) {
    char narrow[1024]{};
    if (!narrow_path(narrow, sizeof(narrow), path)) {
        errno = EINVAL;
        return -1;
    }
    return _mkdir(narrow);
}

OA_XP_DEFINE_LIBRARY(wide_mkdir, _wmkdir);

extern "C" int __cdecl wide_chdir(const wchar_t* path) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wchdir)
);

/// Makes a directory the current one, as _wchdir does, through the narrow
/// _chdir, for the same reason as wide_mkdir above.
///
/// @param path the directory to make current
/// @return 0, or -1 with errno set as _chdir sets it
int __cdecl wide_chdir(const wchar_t* path) {
    char narrow[1024]{};
    if (!narrow_path(narrow, sizeof(narrow), path)) {
        errno = EINVAL;
        return -1;
    }
    return _chdir(narrow);
}

OA_XP_DEFINE_LIBRARY(wide_chdir, _wchdir);

extern "C" int __cdecl wide_chmod(const wchar_t* path, int mode) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wchmod)
);

/// Sets a path's permission bits, as _wchmod does, through the narrow _chmod,
/// for the same reason as wide_mkdir above.
///
/// @param path the path to set the bits of
/// @param mode the bits to set
/// @return 0, or -1 with errno set as _chmod sets it
int __cdecl wide_chmod(const wchar_t* path, int mode) {
    char narrow[1024]{};
    if (!narrow_path(narrow, sizeof(narrow), path)) {
        errno = EINVAL;
        return -1;
    }
    return _chmod(narrow, mode);
}

OA_XP_DEFINE_LIBRARY(wide_chmod, _wchmod);

extern "C" int __cdecl wide_utime(const wchar_t* path, struct _utimbuf* times)
    __asm__(OA_XP_LIBRARY_SYMBOL(_wutime));

/// Sets a path's times, as _wutime does, through the narrow _utime, for the
/// same reason as wide_mkdir above. The two take the same structure.
///
/// @param path the path to set the times of
/// @param times the times to set, or null for the present time
/// @return 0, or -1 with errno set as _utime sets it
int __cdecl wide_utime(const wchar_t* path, struct _utimbuf* times) {
    char narrow[1024]{};
    if (!narrow_path(narrow, sizeof(narrow), path)) {
        errno = EINVAL;
        return -1;
    }
    return _utime(narrow, times);
}

OA_XP_DEFINE_LIBRARY(wide_utime, _wutime);

extern "C" wchar_t* __cdecl wide_getcwd(wchar_t* buffer, int maxlen) __asm__(
    OA_XP_LIBRARY_SYMBOL(_wgetcwd)
);

/// Gives the current directory, as _wgetcwd does, from the narrow _getcwd, for
/// the same reason as wide_mkdir above — and here the wide call answers NULL
/// for a directory that is plainly current.
///
/// A caller that gives no buffer is given an allocated path, which it frees,
/// so the path is widened into memory the C library's own allocation holds.
///
/// @param buffer where the path goes, or null to have one allocated
/// @param maxlen how many characters buffer holds, unread when it is null
/// @return buffer, the allocated path, or null with errno set
wchar_t* __cdecl wide_getcwd(wchar_t* buffer, int maxlen) {
    char narrow[1024]{};
    if (_getcwd(narrow, static_cast<int>(sizeof(narrow))) == nullptr)
        return nullptr;
    if (buffer == nullptr) {
        const int needed = MultiByteToWideChar(CP_ACP, 0, narrow, -1, nullptr, 0);
        if (needed <= 0) {
            errno = EINVAL;
            return nullptr;
        }
        auto* wide = static_cast<wchar_t*>(
            std::malloc(sizeof(wchar_t) * static_cast<size_t>(needed))
        );
        if (wide == nullptr) {
            errno = ENOMEM;
            return nullptr;
        }
        MultiByteToWideChar(CP_ACP, 0, narrow, -1, wide, needed);
        return wide;
    }
    if (maxlen <= 0) {
        errno = EINVAL;
        return nullptr;
    }
    if (MultiByteToWideChar(CP_ACP, 0, narrow, -1, buffer, maxlen) <= 0) {
        errno = ERANGE;
        return nullptr;
    }
    return buffer;
}

OA_XP_DEFINE_LIBRARY(wide_getcwd, _wgetcwd);

// The condition variable of the Windows API, which Windows Vista added and
// Windows 95 has not. The C++ run-time library's thread support is told that
// the version compiled for has one (cmake/toolchains/windows-95-gthr.hpp) and
// builds its condition variables on these calls. The two that wake a waiter
// are defined beside the slim locks above; making one, and sleeping on one
// over a critical section, are defined here, over the same word.

/// Makes a condition that no thread waits on.
extern "C" void WINAPI
initialize_condition_variable(void** condition) __asm__(
    OA_XP_SYSTEM_SYMBOL(InitializeConditionVariable, 4)
);

void WINAPI initialize_condition_variable(void** condition) {
    word_of(condition) = 0;
}

OA_XP_DEFINE_SYSTEM(initialize_condition_variable, InitializeConditionVariable, 4);

/// Releases the lock, waits for the condition to be woken, and takes the lock
/// again.
///
/// @return TRUE when woken, or FALSE with ERROR_TIMEOUT when the time ran out
extern "C" BOOL WINAPI sleep_condition_variable_cs(
    void** condition, void* section, DWORD timeout_ms
) __asm__(OA_XP_SYSTEM_SYMBOL(SleepConditionVariableCS, 12));

BOOL WINAPI sleep_condition_variable_cs(void** condition, void* section, DWORD timeout_ms) {
    // The count is noted before the lock is released, so a wake that comes
    // between the two is not lost.
    const uintptr_t noted = xp::note_condition(word_of(condition));
    auto* lock = static_cast<LPCRITICAL_SECTION>(section);
    LeaveCriticalSection(lock);
    const bool woken = xp::wait_condition_word(
        word_of(condition), noted, timeout_ms == INFINITE ? xp::wait_forever : timeout_ms
    );
    EnterCriticalSection(lock);
    if (!woken) {
        SetLastError(ERROR_TIMEOUT);
        return FALSE;
    }
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(sleep_condition_variable_cs, SleepConditionVariableCS, 12);

// libgcc's unwinder, which the C++ run-time library calls to run a handler.
extern "C" void* _Unwind_Find_FDE(const void* at, void* bases);
extern "C" void __register_frame_info(const void* begin, void* object);

namespace {

/// The bytes a PE image keeps a section's name in, which is one byte short of
/// the name `.eh_frame` and the reason the section is found as `.eh_fram`.
constexpr int kSectionNameBytes = 8;
/// The first eight bytes of the section holding the frame descriptors, which
/// is the whole of the name where the image truncated it and the start of it
/// where the image kept it.
constexpr const char* const kFrameSectionName = ".eh_fram";
/// Room for the object libgcc fills in when the frame information is
/// registered. Its size is libgcc's, not this program's, so it is generous.
char frame_object[512];

/// Whether the unwinder can find the frame descriptor for an address, which is
/// all it needs before a handler can be run. This is libgcc's own exported
/// lookup, so the answer is its rather than a stand-in's.
[[nodiscard]] bool frame_descriptor_found(std::uintptr_t address) noexcept {
    void* bases[3] = {nullptr, nullptr, nullptr};
    return _Unwind_Find_FDE(reinterpret_cast<const void*>(address), bases) != nullptr;
}

/// Finds the program's frame descriptors in its own image.
///
/// @param[out] begin receives the section's address
/// @param[out] size receives the section's length in bytes
/// @return whether the image has such a section
bool frame_section(const unsigned char** begin, unsigned* size) noexcept {
    const auto* image = reinterpret_cast<const unsigned char*>(GetModuleHandleA(nullptr));
    if (image == nullptr)
        return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    const auto* windows = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
    if (windows->Signature != IMAGE_NT_SIGNATURE)
        return false;

    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(windows);
    for (int index = 0; index < windows->FileHeader.NumberOfSections; ++index, ++section) {
        if (std::strncmp(
                reinterpret_cast<const char*>(section->Name), kFrameSectionName, kSectionNameBytes
            ) != 0) {
            continue;
        }
        if (section->Misc.VirtualSize == 0)
            return false;
        *begin = image + section->VirtualAddress;
        *size = section->Misc.VirtualSize;
        return true;
    }
    return false;
}

} // namespace

/// Registers this program's frame information when the toolchain left it
/// unregistered, so that a thrown C++ exception can be caught.
///
/// The C++ run-time library runs a handler by calling libgcc's unwinder, which
/// looks up the frame descriptor of each address on the way down. It finds them
/// through a table that `__register_frame_info` fills, and the start-up the
/// MinGW toolchain supplies here never calls that function. The table stays
/// empty, every lookup fails, and libgcc aborts the process rather than running
/// the handler — measured on this toolchain: `_Unwind_Find_FDE` reports nothing
/// for an address inside the program's own `main`, and a `throw` inside a `try`
/// ends the process with exit code 3 without the `catch` having run. Registering
/// the region makes the same lookup find the descriptor and the handler run.
///
/// It registers only where the lookup is already failing, so a toolchain whose
/// start-up does call the function is left alone, and it runs as an early
/// constructor so that a throw during any later start-up is caught too.
__attribute__((constructor(101))) void register_frame_information() noexcept {
    if (frame_descriptor_found(reinterpret_cast<std::uintptr_t>(&register_frame_information)))
        return;

    const unsigned char* begin = nullptr;
    unsigned size = 0;
    if (!frame_section(&begin, &size))
        return;
    __register_frame_info(begin, frame_object);
}

