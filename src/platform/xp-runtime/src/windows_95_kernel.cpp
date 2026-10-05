// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

// The kernel32 functions that Windows 95 does not export and that the C++
// run-time library and SDL call, defined under the names a program imports
// them by. A program linked with this file calls these in place of the
// system's; each uses the system's own function when the running Windows has
// it and a stand-in when it does not, as the file beside this one does for
// the functions Windows XP lacks. Built only for MinGW, whose import naming
// it follows.
//
// The macro and SystemFunction definitions below are the file beside this
// one's; the two share no header yet.

#include "oa/platform/xp_runtime.hpp"

// The declarations of Windows XP, so that none of the functions defined here
// is also declared as the system's.
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#undef WINVER
#define WINVER 0x0501
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <cstring>
#include <cwchar>
#include <iterator>

// The symbol a function is defined by, and the import pointer a program
// calls it through, in MinGW's naming: on 32-bit x86 a leading underscore,
// and for the system's functions the size of their arguments.
#if defined(__i386__)
#define OA_XP_SYSTEM_SYMBOL(name, argument_bytes) "_" #name "@" #argument_bytes
#define OA_XP_SYSTEM_IMPORT(name, argument_bytes) "__imp__" #name "@" #argument_bytes
#else
#define OA_XP_SYSTEM_SYMBOL(name, argument_bytes) #name
#define OA_XP_SYSTEM_IMPORT(name, argument_bytes) "__imp_" #name
#endif

// Defines `function`, declared before with its type, as the system function
// `name` and as the import pointer a program calls `name` through.
#define OA_XP_DEFINE_SYSTEM(function, name, argument_bytes)                                        \
    extern "C" constinit decltype(&function)                                                       \
        const function##_import __asm__(OA_XP_SYSTEM_IMPORT(name, argument_bytes)) = &function

namespace {

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
                found =
                    reinterpret_cast<Function>(reinterpret_cast<void*>(GetProcAddress(module, name)));
            function.store(found, std::memory_order_relaxed);
            looked_up.store(true, std::memory_order_release);
        }
        return function.load(std::memory_order_relaxed);
    }
};

constexpr wchar_t kernel32[] = L"kernel32.dll";

} // namespace

// The version a program asks about, and the conditions it asks with. Both
// calls are needed for one question and are kept together: the mask one makes
// is the mask the other reads.

namespace {

using AddVectoredHandlerFunction =
    PVOID(WINAPI*)(ULONG first, PVECTORED_EXCEPTION_HANDLER handler);
using RemoveVectoredHandlerFunction = ULONG(WINAPI*)(PVOID handler);
using AttachConsoleFunction = BOOL(WINAPI*)(DWORD process_id);
using CancelIoFunction = BOOL(WINAPI*)(HANDLE file);
using CopyFileExFunction = BOOL(WINAPI*)(
    LPCWSTR from, LPCWSTR to, LPPROGRESS_ROUTINE progress, LPVOID data, LPBOOL cancel, DWORD flags
);
using CreateHardLinkFunction =
    BOOL(WINAPI*)(LPCWSTR file, LPCWSTR existing, LPSECURITY_ATTRIBUTES attributes);
using FindFirstFileExFunction = HANDLE(WINAPI*)(
    LPCWSTR name, FINDEX_INFO_LEVELS level, LPVOID data, FINDEX_SEARCH_OPS search, LPVOID filter,
    DWORD flags
);
using GetFileAttributesExFunction =
    BOOL(WINAPI*)(LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID data);
using GetDiskFreeSpaceExFunction = BOOL(WINAPI*)(
    LPCWSTR directory, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER free
);
using GetFileSizeExFunction = BOOL(WINAPI*)(HANDLE file, PLARGE_INTEGER size);
using GetLongPathNameFunction = DWORD(WINAPI*)(LPCWSTR name, LPWSTR long_name, DWORD capacity);
using GetModuleHandleExFunction = BOOL(WINAPI*)(DWORD flags, LPCWSTR name, HMODULE* module);
using GetUserDefaultUILanguageFunction = LANGID(WINAPI*)(void);
using GlobalMemoryStatusExFunction = BOOL(WINAPI*)(LPMEMORYSTATUSEX status);
using InitializeCriticalSectionAndSpinCountFunction =
    BOOL(WINAPI*)(LPCRITICAL_SECTION section, DWORD spin_count);
using IsWow64ProcessFunction = BOOL(WINAPI*)(HANDLE process, PBOOL wow64);
using SetFilePointerExFunction =
    BOOL(WINAPI*)(HANDLE file, LARGE_INTEGER distance, PLARGE_INTEGER position, DWORD method);
using SetThreadExecutionStateFunction = EXECUTION_STATE(WINAPI*)(EXECUTION_STATE state);
using TryEnterCriticalSectionFunction = BOOL(WINAPI*)(LPCRITICAL_SECTION section);
using VerSetConditionMaskFunction = ULONGLONG(WINAPI*)(ULONGLONG mask, DWORD type, BYTE condition);
using VerifyVersionInfoFunction =
    BOOL(WINAPI*)(LPOSVERSIONINFOEXW wanted, DWORD type, DWORDLONG mask);

constinit SystemFunction<AddVectoredHandlerFunction> system_add_vectored_handler{
    kernel32, "AddVectoredExceptionHandler"
};
constinit SystemFunction<RemoveVectoredHandlerFunction> system_remove_vectored_handler{
    kernel32, "RemoveVectoredExceptionHandler"
};
constinit SystemFunction<AttachConsoleFunction> system_attach_console{kernel32, "AttachConsole"};
constinit SystemFunction<CancelIoFunction> system_cancel_io{kernel32, "CancelIo"};
constinit SystemFunction<CopyFileExFunction> system_copy_file_ex{kernel32, "CopyFileExW"};
constinit SystemFunction<CreateHardLinkFunction> system_create_hard_link{
    kernel32, "CreateHardLinkW"
};
constinit SystemFunction<FindFirstFileExFunction> system_find_first_file_ex{
    kernel32, "FindFirstFileExW"
};
constinit SystemFunction<GetDiskFreeSpaceExFunction> system_get_disk_free_space_ex{
    kernel32, "GetDiskFreeSpaceExW"
};
constinit SystemFunction<GetFileAttributesExFunction> system_get_file_attributes_ex{
    kernel32, "GetFileAttributesExW"
};
constinit SystemFunction<GetFileSizeExFunction> system_get_file_size_ex{
    kernel32, "GetFileSizeEx"
};
constinit SystemFunction<GetLongPathNameFunction> system_get_long_path_name{
    kernel32, "GetLongPathNameW"
};
constinit SystemFunction<GetModuleHandleExFunction> system_get_module_handle_ex{
    kernel32, "GetModuleHandleExW"
};
constinit SystemFunction<GetUserDefaultUILanguageFunction> system_get_user_default_ui_language{
    kernel32, "GetUserDefaultUILanguage"
};
constinit SystemFunction<GlobalMemoryStatusExFunction> system_global_memory_status_ex{
    kernel32, "GlobalMemoryStatusEx"
};
constinit SystemFunction<InitializeCriticalSectionAndSpinCountFunction>
    system_initialize_critical_section_and_spin_count{
        kernel32, "InitializeCriticalSectionAndSpinCount"
    };
constinit SystemFunction<IsWow64ProcessFunction> system_is_wow64_process{
    kernel32, "IsWow64Process"
};
constinit SystemFunction<SetFilePointerExFunction> system_set_file_pointer_ex{
    kernel32, "SetFilePointerEx"
};
constinit SystemFunction<SetThreadExecutionStateFunction> system_set_thread_execution_state{
    kernel32, "SetThreadExecutionState"
};
constinit SystemFunction<TryEnterCriticalSectionFunction> system_try_enter_critical_section{
    kernel32, "TryEnterCriticalSection"
};
constinit SystemFunction<VerSetConditionMaskFunction> system_ver_set_condition_mask{
    kernel32, "VerSetConditionMask"
};
constinit SystemFunction<VerifyVersionInfoFunction> system_verify_version_info{
    kernel32, "VerifyVersionInfoW"
};

/// The version fields a mask names, in the order their bits sit in it: a
/// field's condition occupies three bits at three times its index.
constexpr DWORD version_fields[] = {
    VER_MINORVERSION,     VER_MAJORVERSION,       VER_BUILDNUMBER, VER_PLATFORMID,
    VER_SERVICEPACKMINOR, VER_SERVICEPACKMAJOR,   VER_SUITENAME,   VER_PRODUCT_TYPE,
};

/// The value one version field of a description holds.
///
/// @param version the description
/// @param field index into version_fields
/// @return the field's value
DWORD version_field_value(const OSVERSIONINFOEXW& version, std::size_t field) noexcept {
    switch (field) {
    case 0:
        return version.dwMinorVersion;
    case 1:
        return version.dwMajorVersion;
    case 2:
        return version.dwBuildNumber;
    case 3:
        return version.dwPlatformId;
    case 4:
        return version.wServicePackMinor;
    case 5:
        return version.wServicePackMajor;
    case 6:
        return version.wSuiteMask;
    default:
        return version.wProductType;
    }
}

/// Whether a field's value meets the condition the mask holds for it.
///
/// @param value the running Windows' value
/// @param wanted the description's value
/// @param condition the three-bit condition, one of the VER_ ones
/// @return true when the condition holds
bool version_meets_condition(DWORD value, DWORD wanted, BYTE condition) noexcept {
    switch (condition) {
    case VER_EQUAL:
        return value == wanted;
    case VER_GREATER:
        return value > wanted;
    case VER_GREATER_EQUAL:
        return value >= wanted;
    case VER_LESS:
        return value < wanted;
    case VER_LESS_EQUAL:
        return value <= wanted;
    case VER_AND:
        return (value & wanted) == wanted;
    case VER_OR:
        return (value & wanted) != 0;
    default:
        return false;
    }
}

} // namespace

/// Reports that a thread's exceptions may be seen before the system handles
/// them.
///
/// Windows 95 has no vectored handlers, so none runs; a caller installs one to
/// watch its own threads, and reporting the installation with the handler as
/// the token a later removal passes back costs nothing.
///
/// @param first true to see exceptions before the system's handling, false after
/// @param handler the handler to install
/// @return the token to remove with, which is the handler
extern "C" PVOID WINAPI add_vectored_exception_handler(
    ULONG first, PVECTORED_EXCEPTION_HANDLER handler
) __asm__(OA_XP_SYSTEM_SYMBOL(AddVectoredExceptionHandler, 8));

PVOID WINAPI
add_vectored_exception_handler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
    if (const auto system = system_add_vectored_handler.get())
        return system(first, handler);
    return reinterpret_cast<PVOID>(handler);
}

OA_XP_DEFINE_SYSTEM(add_vectored_exception_handler, AddVectoredExceptionHandler, 8);

/// Removes a handler add_vectored_exception_handler installed.
///
/// @param handler the token that call returned
/// @return true
extern "C" ULONG WINAPI
remove_vectored_exception_handler(PVOID handler) __asm__(
    OA_XP_SYSTEM_SYMBOL(RemoveVectoredExceptionHandler, 4)
);

ULONG WINAPI remove_vectored_exception_handler(PVOID handler) {
    if (const auto system = system_remove_vectored_handler.get())
        return system(handler);
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(remove_vectored_exception_handler, RemoveVectoredExceptionHandler, 4);

/// Attaches the calling process to a console's.
///
/// Windows 95 has no console subsystem, so there is none to attach to.
///
/// @param process_id the process whose console to attach to
/// @return false, with the last error saying the call is not there
extern "C" BOOL WINAPI
attach_console(DWORD process_id) __asm__(OA_XP_SYSTEM_SYMBOL(AttachConsole, 4));

BOOL WINAPI attach_console(DWORD process_id) {
    if (const auto system = system_attach_console.get())
        return system(process_id);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(attach_console, AttachConsole, 4);

/// Cancels the input and output a file has outstanding.
///
/// Windows 95 has no asynchronous input and output to cancel.
///
/// @param file the file whose input and output to cancel
/// @return false, with the last error saying the call is not supported
extern "C" BOOL WINAPI cancel_io(HANDLE file) __asm__(OA_XP_SYSTEM_SYMBOL(CancelIo, 4));

BOOL WINAPI cancel_io(HANDLE file) {
    if (const auto system = system_cancel_io.get())
        return system(file);
    (void)file;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(cancel_io, CancelIo, 4);

/// Copies a file, with a caller that may watch its progress.
///
/// Windows 95 copies a file whole, with no progress to report, which is what a
/// caller that asked for progress gets: none, and the copy.
///
/// @param from the file to copy
/// @param to the file to write
/// @param progress the caller's progress function, never called here
/// @param data the value to pass the progress function
/// @param[out] cancel the caller's cancel flag, set false
/// @param flags COPY_FILE_* flags
/// @return true when the file was copied
extern "C" BOOL WINAPI copy_file_ex(
    LPCWSTR from, LPCWSTR to, LPPROGRESS_ROUTINE progress, LPVOID data, LPBOOL cancel, DWORD flags
) __asm__(OA_XP_SYSTEM_SYMBOL(CopyFileExW, 24));

BOOL WINAPI copy_file_ex(
    LPCWSTR from, LPCWSTR to, LPPROGRESS_ROUTINE progress, LPVOID data, LPBOOL cancel, DWORD flags
) {
    if (const auto system = system_copy_file_ex.get())
        return system(from, to, progress, data, cancel, flags);
    (void)progress;
    (void)data;
    if (cancel != nullptr)
        *cancel = FALSE;
    return CopyFileW(from, to, (flags & COPY_FILE_FAIL_IF_EXISTS) != 0);
}

OA_XP_DEFINE_SYSTEM(copy_file_ex, CopyFileExW, 24);

/// Makes a second name for a file.
///
/// Windows 95 has no hard links, on no filing system it holds.
///
/// @param file the name to make
/// @param existing the file it names
/// @param attributes ignored
/// @return false, with the last error saying the call is not supported
extern "C" BOOL WINAPI create_hard_link_w(
    LPCWSTR file, LPCWSTR existing, LPSECURITY_ATTRIBUTES attributes
) __asm__(OA_XP_SYSTEM_SYMBOL(CreateHardLinkW, 12));

BOOL WINAPI
create_hard_link_w(LPCWSTR file, LPCWSTR existing, LPSECURITY_ATTRIBUTES attributes) {
    if (const auto system = system_create_hard_link.get())
        return system(file, existing, attributes);
    (void)file;
    (void)existing;
    (void)attributes;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(create_hard_link_w, CreateHardLinkW, 12);

/// Finds the first name a pattern names.
///
/// Windows 95 searches by name alone, so the caller's level, search operation
/// and filter are not used; the name a caller searched with is the one it gets.
///
/// @param name the pattern to search with
/// @param level which fields of the find data to fill, ignored
/// @param[out] data the WIN32_FIND_DATA the search fills
/// @param search which names to search for, ignored
/// @param filter a filter for the search, ignored
/// @param flags search flags, ignored
/// @return the search handle, or INVALID_HANDLE_VALUE with the last error set
extern "C" HANDLE WINAPI find_first_file_ex(
    LPCWSTR name, FINDEX_INFO_LEVELS level, LPVOID data, FINDEX_SEARCH_OPS search, LPVOID filter,
    DWORD flags
) __asm__(OA_XP_SYSTEM_SYMBOL(FindFirstFileExW, 24));

HANDLE WINAPI find_first_file_ex(
    LPCWSTR name, FINDEX_INFO_LEVELS level, LPVOID data, FINDEX_SEARCH_OPS search, LPVOID filter,
    DWORD flags
) {
    if (const auto system = system_find_first_file_ex.get())
        return system(name, level, data, search, filter, flags);
    (void)level;
    (void)search;
    (void)filter;
    (void)flags;
    return FindFirstFileW(name, static_cast<LPWIN32_FIND_DATAW>(data));
}

OA_XP_DEFINE_SYSTEM(find_first_file_ex, FindFirstFileExW, 24);

/// Reads a file's attributes, its size and the times its entries hold.
///
/// Windows 95 answers the same search that finds a name, which holds all of
/// those for it.
///
/// @param name the file to read
/// @param level which information to read, which must be the standard one
/// @param[out] data the WIN32_FILE_ATTRIBUTE_DATA to fill
/// @return true when the file was read
extern "C" BOOL WINAPI get_file_attributes_ex(
    LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID data
) __asm__(OA_XP_SYSTEM_SYMBOL(GetFileAttributesExW, 12));

BOOL WINAPI get_file_attributes_ex(LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID data) {
    if (const auto system = system_get_file_attributes_ex.get())
        return system(name, level, data);
    if (level != GetFileExInfoStandard || data == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    WIN32_FIND_DATAW found{};
    const HANDLE search = FindFirstFileW(name, &found);
    if (search == INVALID_HANDLE_VALUE)
        return FALSE;
    FindClose(search);
    auto* attributes = static_cast<LPWIN32_FILE_ATTRIBUTE_DATA>(data);
    attributes->dwFileAttributes = found.dwFileAttributes;
    attributes->ftCreationTime = found.ftCreationTime;
    attributes->ftLastAccessTime = found.ftLastAccessTime;
    attributes->ftLastWriteTime = found.ftLastWriteTime;
    attributes->nFileSizeHigh = found.nFileSizeHigh;
    attributes->nFileSizeLow = found.nFileSizeLow;
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(get_file_attributes_ex, GetFileAttributesExW, 12);

/// Reads a volume's size and the room left on it.
///
/// Windows 95 RTM has only the call that answers in clusters, which the three
/// totals the caller asks for are worked out from; OSR2 and every later
/// Windows have this one.
///
/// @param directory a folder on the volume
/// @param[out] available the room the calling user may use
/// @param[out] total the volume's size
/// @param[out] free_space the room free on it
/// @return true when the volume was read
extern "C" BOOL WINAPI get_disk_free_space_ex(
    LPCWSTR directory, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER free_space
) __asm__(OA_XP_SYSTEM_SYMBOL(GetDiskFreeSpaceExW, 16));

BOOL WINAPI get_disk_free_space_ex(
    LPCWSTR directory, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER free_space
) {
    if (const auto system = system_get_disk_free_space_ex.get())
        return system(directory, available, total, free_space);
    char narrow[MAX_PATH + 1]{};
    if (WideCharToMultiByte(CP_ACP, 0, directory, -1, narrow, sizeof(narrow), nullptr, nullptr) == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    DWORD sectors_per_cluster = 0;
    DWORD bytes_per_sector = 0;
    DWORD free_clusters = 0;
    DWORD all_clusters = 0;
    if (GetDiskFreeSpaceA(
            narrow, &sectors_per_cluster, &bytes_per_sector, &free_clusters, &all_clusters
        ) == FALSE)
        return FALSE;
    const ULONGLONG cluster_bytes =
        static_cast<ULONGLONG>(sectors_per_cluster) * bytes_per_sector;
    if (available != nullptr)
        available->QuadPart = cluster_bytes * free_clusters;
    if (total != nullptr)
        total->QuadPart = cluster_bytes * all_clusters;
    if (free_space != nullptr)
        free_space->QuadPart = cluster_bytes * free_clusters;
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(get_disk_free_space_ex, GetDiskFreeSpaceExW, 16);

/// Reads a file's size, which Windows 95 answers in two halves.
///
/// @param file the file to read
/// @param[out] size the size in bytes
/// @return true when the size was read
extern "C" BOOL WINAPI
get_file_size_ex(HANDLE file, PLARGE_INTEGER size) __asm__(
    OA_XP_SYSTEM_SYMBOL(GetFileSizeEx, 8)
);

BOOL WINAPI get_file_size_ex(HANDLE file, PLARGE_INTEGER size) {
    if (const auto system = system_get_file_size_ex.get())
        return system(file, size);
    if (size == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    DWORD high = 0;
    const DWORD low = GetFileSize(file, &high);
    if (low == INVALID_FILE_SIZE && GetLastError() != NO_ERROR)
        return FALSE;
    size->LowPart = low;
    size->HighPart = static_cast<LONG>(high);
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(get_file_size_ex, GetFileSizeEx, 8);

/// Gives a name in the long form a program asks for.
///
/// Windows 95 OSR2 and every later Windows keep only long names, so a name is
/// already the long one asked for and is given back as it came.
///
/// @param name the name to read
/// @param[out] long_name the name, whose space is filled
/// @param capacity the characters long_name holds
/// @return the characters written without the terminator, or the characters
/// the name needs, terminator included, when capacity is too small for it
extern "C" DWORD WINAPI get_long_path_name(
    LPCWSTR name, LPWSTR long_name, DWORD capacity
) __asm__(OA_XP_SYSTEM_SYMBOL(GetLongPathNameW, 12));

DWORD WINAPI get_long_path_name(LPCWSTR name, LPWSTR long_name, DWORD capacity) {
    if (const auto system = system_get_long_path_name.get())
        return system(name, long_name, capacity);
    if (name == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    const std::size_t length = std::wcslen(name);
    const DWORD needed = static_cast<DWORD>(length + 1);
    if (long_name == nullptr || capacity == 0)
        return needed;
    if (capacity < needed)
        return needed;
    std::memcpy(long_name, name, needed * sizeof(wchar_t));
    return static_cast<DWORD>(length);
}

OA_XP_DEFINE_SYSTEM(get_long_path_name, GetLongPathNameW, 12);

/// Takes the handle of the module a name or an address names.
///
/// Windows 95 has no reference counting to keep or to leave unchanged, so only
/// the address and the name are used.
///
/// @param flags GET_MODULE_HANDLE_EX_FLAG_ ones
/// @param name the module's name, or an address in it
/// @param[out] module the module's handle
/// @return true when the module was found
extern "C" BOOL WINAPI get_module_handle_ex(
    DWORD flags, LPCWSTR name, HMODULE* module
) __asm__(OA_XP_SYSTEM_SYMBOL(GetModuleHandleExW, 12));

BOOL WINAPI get_module_handle_ex(DWORD flags, LPCWSTR name, HMODULE* module) {
    if (const auto system = system_get_module_handle_ex.get())
        return system(flags, name, module);
    if (module == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    HMODULE found = nullptr;
    if ((flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) != 0) {
        MEMORY_BASIC_INFORMATION mapped{};
        if (VirtualQuery(name, &mapped, sizeof(mapped)) == 0) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            return FALSE;
        }
        found = static_cast<HMODULE>(mapped.AllocationBase);
    } else {
        found = GetModuleHandleW(name);
    }
    if (found == nullptr)
        return FALSE;
    *module = found;
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(get_module_handle_ex, GetModuleHandleExW, 12);

/// Gives the language of the user's own interface.
///
/// Windows 95 draws its interface in the user's language, which is the one
/// this call gives.
///
/// @return the user's language
extern "C" LANGID WINAPI
get_user_default_ui_language(void) __asm__(
    OA_XP_SYSTEM_SYMBOL(GetUserDefaultUILanguage, 0)
);

LANGID WINAPI get_user_default_ui_language(void) {
    if (const auto system = system_get_user_default_ui_language.get())
        return system();
    return GetUserDefaultLangID();
}

OA_XP_DEFINE_SYSTEM(get_user_default_ui_language, GetUserDefaultUILanguage, 0);

/// Reads how much memory the machine has and how much is left.
///
/// Windows 95 answers for physical memory and for the swap file together and
/// for each separately, which is all the longer report holds.
///
/// @param[out] status the MEMORYSTATUSEX to fill, whose length the caller sets
/// @return true when the report was filled
extern "C" BOOL WINAPI
global_memory_status_ex(LPMEMORYSTATUSEX status) __asm__(
    OA_XP_SYSTEM_SYMBOL(GlobalMemoryStatusEx, 4)
);

BOOL WINAPI global_memory_status_ex(LPMEMORYSTATUSEX status) {
    if (const auto system = system_global_memory_status_ex.get())
        return system(status);
    if (status == nullptr || status->dwLength < sizeof(MEMORYSTATUSEX)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    MEMORYSTATUS plain{};
    plain.dwLength = sizeof(plain);
    GlobalMemoryStatus(&plain);
    status->dwMemoryLoad = plain.dwMemoryLoad;
    status->ullTotalPhys = plain.dwTotalPhys;
    status->ullAvailPhys = plain.dwAvailPhys;
    status->ullTotalPageFile = plain.dwTotalPageFile;
    status->ullAvailPageFile = plain.dwAvailPageFile;
    status->ullTotalVirtual = plain.dwTotalVirtual;
    status->ullAvailVirtual = plain.dwAvailVirtual;
    status->ullAvailExtendedVirtual = 0;
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(global_memory_status_ex, GlobalMemoryStatusEx, 4);

/// Makes a lock ready for threads to take, with a count of times a thread
/// waits on the processor before it sleeps.
///
/// Windows 95's lock has no such count; every other part of making it ready is
/// the same, so the lock is ready and the count is not kept.
///
/// @param[out] section the lock to make ready
/// @param spin_count how many times a waiting thread spins first, ignored
/// @return true
extern "C" BOOL WINAPI initialize_critical_section_and_spin_count(
    LPCRITICAL_SECTION section, DWORD spin_count
) __asm__(OA_XP_SYSTEM_SYMBOL(InitializeCriticalSectionAndSpinCount, 8));

BOOL WINAPI
initialize_critical_section_and_spin_count(LPCRITICAL_SECTION section, DWORD spin_count) {
    if (const auto system = system_initialize_critical_section_and_spin_count.get())
        return system(section, spin_count);
    (void)spin_count;
    InitializeCriticalSection(section);
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(
    initialize_critical_section_and_spin_count, InitializeCriticalSectionAndSpinCount, 8
);

/// Says whether a process runs as a 32-bit program on 64-bit Windows.
///
/// Windows 95 is not 64-bit and emulates no such program, so no process does.
///
/// @param process the process to ask about
/// @param[out] wow64 false
/// @return true when the answer was given
extern "C" BOOL WINAPI
is_wow64_process(HANDLE process, PBOOL wow64) __asm__(
    OA_XP_SYSTEM_SYMBOL(IsWow64Process, 8)
);

BOOL WINAPI is_wow64_process(HANDLE process, PBOOL wow64) {
    if (const auto system = system_is_wow64_process.get())
        return system(process, wow64);
    (void)process;
    if (wow64 == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *wow64 = FALSE;
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(is_wow64_process, IsWow64Process, 8);

/// Moves a file's place to read and to write from.
///
/// Windows 95 moves it in two halves, the low one this call gives back and the
/// high one it writes beside it.
///
/// @param file the file to move in
/// @param distance how far to move
/// @param[out] position the place moved to, which the caller may pass as null
/// @param method where the move starts from, a FILE_BEGIN, FILE_CURRENT or
/// FILE_END
/// @return true when the file moved
extern "C" BOOL WINAPI set_file_pointer_ex(
    HANDLE file, LARGE_INTEGER distance, PLARGE_INTEGER position, DWORD method
) __asm__(OA_XP_SYSTEM_SYMBOL(SetFilePointerEx, 20));

BOOL WINAPI set_file_pointer_ex(
    HANDLE file, LARGE_INTEGER distance, PLARGE_INTEGER position, DWORD method
) {
    if (const auto system = system_set_file_pointer_ex.get())
        return system(file, distance, position, method);
    LARGE_INTEGER moved{};
    moved.LowPart = SetFilePointer(file, distance.LowPart, &distance.HighPart, method);
    if (moved.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
        return FALSE;
    moved.HighPart = distance.HighPart;
    if (position != nullptr)
        *position = moved;
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(set_file_pointer_ex, SetFilePointerEx, 20);

/// Keeps the machine awake, or lets it sleep, while the thread runs.
///
/// Windows 95 has no power management for a program to ask for, so nothing
/// sleeps that would not have; a caller that asked for the machine to stay
/// awake is told it does.
///
/// @param state the ES_ flags to set
/// @return the flags passed
extern "C" EXECUTION_STATE WINAPI
set_thread_execution_state(EXECUTION_STATE state) __asm__(
    OA_XP_SYSTEM_SYMBOL(SetThreadExecutionState, 4)
);

EXECUTION_STATE WINAPI set_thread_execution_state(EXECUTION_STATE state) {
    if (const auto system = system_set_thread_execution_state.get())
        return system(state);
    return state;
}

OA_XP_DEFINE_SYSTEM(set_thread_execution_state, SetThreadExecutionState, 4);

/// Takes a lock a thread holds, or finds that another thread does.
///
/// Windows 95's lock does not say whether it is free, but a lock no thread
/// holds holds a count of -1, which the one step below takes while leaving it
/// a word a second thread's step will not; a thread that already holds the
/// lock takes it again.
///
/// @param[in,out] section the lock to take
/// @return true when the calling thread now holds it
extern "C" BOOL WINAPI
try_enter_critical_section(LPCRITICAL_SECTION section) __asm__(
    OA_XP_SYSTEM_SYMBOL(TryEnterCriticalSection, 4)
);

BOOL WINAPI try_enter_critical_section(LPCRITICAL_SECTION section) {
    if (const auto system = system_try_enter_critical_section.get())
        return system(section);
    const HANDLE thread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetCurrentThreadId()));
    if (InterlockedCompareExchange(&section->LockCount, 0, -1) == -1) {
        section->RecursionCount = 1;
        section->OwningThread = thread;
        return TRUE;
    }
    if (section->OwningThread == thread) {
        InterlockedIncrement(&section->LockCount);
        ++section->RecursionCount;
        return TRUE;
    }
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(try_enter_critical_section, TryEnterCriticalSection, 4);

/// Adds a condition to the mask VerifyVersionInfoW compares with.
///
/// A field's condition sits in the three bits at three times the field's
/// place, which is where the compare below reads it.
///
/// @param mask the mask so far
/// @param type the version field to set the condition for, one VER_ bit
/// @param condition how the field is to compare, one of the VER_ conditions
/// @return the mask with the condition added
extern "C" ULONGLONG WINAPI ver_set_condition_mask(
    ULONGLONG mask, DWORD type, BYTE condition
) __asm__(OA_XP_SYSTEM_SYMBOL(VerSetConditionMask, 16));

ULONGLONG WINAPI ver_set_condition_mask(ULONGLONG mask, DWORD type, BYTE condition) {
    if (const auto system = system_ver_set_condition_mask.get())
        return system(mask, type, condition);
    for (std::size_t field = 0; field < std::size(version_fields); ++field) {
        if (type == version_fields[field])
            return mask | (static_cast<ULONGLONG>(condition) << (field * 3));
    }
    return mask;
}

OA_XP_DEFINE_SYSTEM(ver_set_condition_mask, VerSetConditionMask, 16);

/// Says whether the running Windows meets a described one.
///
/// The description's every field the type names is compared with the running
/// version under the condition the mask holds for it.
///
/// @param wanted the version to compare with
/// @param type the fields to compare, VER_ bits together
/// @param mask the conditions, as ver_set_condition_mask built them
/// @return true when every field meets its condition
extern "C" BOOL WINAPI verify_version_info_w(
    LPOSVERSIONINFOEXW wanted, DWORD type, DWORDLONG mask
) __asm__(OA_XP_SYSTEM_SYMBOL(VerifyVersionInfoW, 16));

BOOL WINAPI verify_version_info_w(LPOSVERSIONINFOEXW wanted, DWORD type, DWORDLONG mask) {
    if (const auto system = system_verify_version_info.get())
        return system(wanted, type, mask);
    if (wanted == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    OSVERSIONINFOEXW running{};
    running.dwOSVersionInfoSize = sizeof(running);
    if (GetVersionExW(reinterpret_cast<LPOSVERSIONINFOW>(&running)) == FALSE)
        return FALSE;
    for (std::size_t field = 0; field < std::size(version_fields); ++field) {
        if ((type & version_fields[field]) == 0)
            continue;
        const auto condition = static_cast<BYTE>((mask >> (field * 3)) & 0x7);
        if (!version_meets_condition(
                version_field_value(running, field), version_field_value(*wanted, field), condition
            )) {
            SetLastError(ERROR_OLD_WIN_VERSION);
            return FALSE;
        }
    }
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(verify_version_info_w, VerifyVersionInfoW, 16);
