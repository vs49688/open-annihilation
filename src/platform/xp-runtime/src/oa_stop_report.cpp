// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

// TEMPORARY diagnostic scaffolding for the Windows 95 investigation.
//
// Nothing on that machine reports a stop: the process aborts with "abnormal
// program termination" and exit code 3, main's catch never runs, so neither
// report_fatal nor the terminate handler says anything, and no log appears.
// This file takes the record where the run time passes through as it dies
// instead of where the program would like to write it — a fault as it is
// raised, the abort call, the abort signal, and an unhandled exception — and
// writes it beside the running image with the Windows calls directly, which is
// the one channel measured to work there.
//
// It also writes every address on the stack that belongs to the running image,
// so a stop on a machine with no debugger can still be named once those
// addresses are read against the program's own symbol table.
//
// Remove this file, and its entry in CMakeLists.txt, once the failing call is
// known.

#include <windows.h>

#include <csignal>
#include <cstdio>
#include <cstring>
#include <exception>
#include <typeinfo>

namespace {

/// The most one line of the report may hold, and how far the address scan goes.
///
/// The scan starts at the faulting thread's own stack pointer rather than this
/// handler's, so the frames it reads are the program's.
constexpr std::size_t line_capacity = 2048;
constexpr unsigned long stack_words = 1024;
/// How many words are also written unmarked, for the frames the image filter
/// misses because the address is a frame pointer rather than a return address.
constexpr unsigned long raw_words = 64;

/// Set while a record is being written, so a fault inside it is not recorded
/// again and the two do not loop.
volatile LONG recording = 0;

/// Appends text, stopping at the buffer's end.
char* put_text(char* at, char* end, const char* text) noexcept {
    while (*text != '\0' && at < end)
        *at++ = *text++;
    return at;
}

/// Appends a number in hexadecimal, exactly `digits` wide.
char* put_hex(char* at, char* end, unsigned long value, int digits) noexcept {
    static const char table[] = "0123456789abcdef";
    for (int index = digits - 1; index >= 0; --index) {
        if (at < end)
            *at++ = table[(value >> (index * 4)) & 0xf];
    }
    return at;
}

/// Appends a number in decimal.
char* put_dec(char* at, char* end, unsigned long value) noexcept {
    char reverse[16] = {};
    int count = 0;
    do {
        reverse[count++] = static_cast<char>('0' + (value % 10));
        value /= 10;
    } while (value != 0 && count < 16);
    while (count > 0 && at < end)
        *at++ = reverse[--count];
    return at;
}

/// Whether an address can be read, asked of the system rather than tried.
///
/// The scan walks a stack that belongs to a process already dying, so it can
/// reach a page that is not there; asking first keeps the record coming from
/// the report rather than from a second fault.
///
/// @param at the address to ask about
/// @return true when reading four bytes there is safe
bool readable(const void* at) noexcept {
    MEMORY_BASIC_INFORMATION where = {};
    if (VirtualQuery(at, &where, sizeof(where)) == 0)
        return false;
    if (where.State != MEM_COMMIT)
        return false;
    const DWORD readable_flags = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                                 | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                                 | PAGE_EXECUTE_WRITECOPY;
    return (where.Protect & readable_flags) != 0;
}

/// Opens the report beside the running image, ready to append.
///
/// The Windows calls directly, not the C library's: this runs while the process
/// is dying and sometimes after the library is torn down, and CreateFileA is
/// measured working there where the wide form is a stub.
///
/// @return the open report, or INVALID_HANDLE_VALUE and the reason in the last
/// error
HANDLE open_report() noexcept {
    char image[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, image, sizeof(image)) == 0)
        return INVALID_HANDLE_VALUE;
    char* slash = std::strrchr(image, '\\');
    if (slash == nullptr)
        return INVALID_HANDLE_VALUE;
    *(slash + 1) = '\0';
    char path[MAX_PATH + 32] = {};
    std::strcpy(path, image);
    std::strcat(path, "oa-stop-report.txt");
    // Generic write and a seek to the end rather than append mode, which is
    // the form every Windows of this age answers.
    HANDLE file = CreateFileA(
        path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr
    );
    if (file == INVALID_HANDLE_VALUE)
        return file;
    SetFilePointer(file, 0, nullptr, FILE_END);
    return file;
}

/// Appends whatever was built in `line`.
///
/// A failure here is said on stderr with the reason, because a report that
/// cannot be written is itself a finding.
void append(HANDLE file, const char* line, std::size_t length) noexcept {
    DWORD written = 0;
    if (!WriteFile(file, line, static_cast<DWORD>(length), &written, nullptr)) {
        const DWORD reason = GetLastError();
        char failure[128] = {};
        char* at = put_text(failure, failure + sizeof(failure) - 1, "open-annihilation: report write failed, error ");
        at = put_dec(at, failure + sizeof(failure) - 1, reason);
        *at++ = '\n';
        std::fwrite(failure, 1, static_cast<std::size_t>(at - failure), stderr);
        std::fflush(stderr);
    }
}

/// Writes the stack words from `from` upward, marking the ones in the image.
///
/// A return address inside the image is a call that led to this point, and read
/// against the program's own symbol table it names the frame. The scan starts
/// at a caller's frame rather than inside this one: a frame holding the
/// report's own buffer is kilobytes wide, and a scan beginning inside it spends
/// its whole budget reading the report's own text back — measured, the first
/// version reported the words `is 0`, `ze=0` and `172d`, which are the lines it
/// had just written.
///
/// @param file the open report, or INVALID_HANDLE_VALUE to write nothing
/// @param from the word to start the scan at
/// @return how many words were read before the scan stopped
unsigned long write_frames(HANDLE file, const unsigned long* from) noexcept {
    const unsigned long base = reinterpret_cast<unsigned long>(GetModuleHandleA(nullptr));
    unsigned long size = 0;
    if (base != 0) {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        size = nt->OptionalHeader.SizeOfImage;
    }
    if (file == INVALID_HANDLE_VALUE || from == nullptr)
        return 0;
    unsigned long read = 0;
    char line[64] = {};
    char* const end = line + sizeof(line) - 2;
    for (unsigned long index = 0; index < stack_words; ++index) {
        if (!readable(&from[index]))
            break;
        ++read;
        const unsigned long word = from[index];
        const bool in_image = base != 0 && word >= base && word < base + size;
        if (!in_image && index >= raw_words)
            continue;
        char* at = line;
        at = put_text(at, end, in_image ? "image " : "stack ");
        at = put_dec(at, end, index);
        *at++ = ' ';
        at = put_hex(at, end, word, 8);
        *at++ = '\n';
        append(file, line, static_cast<std::size_t>(at - line));
    }
    return read;
}

/// Writes why the process is stopping, and where it was.
///
/// @param kind which trap caught the stop
/// @param code the code that came with it, or zero
/// @param where the address the stop happened at, or null
/// @param context the faulting thread's registers, or null when there are none
/// @param access what the fault was doing to memory, or zero
/// @param accessed the address the fault was doing it to, or null
void write_stop(
    const char* kind,
    unsigned long code,
    const void* where,
    const CONTEXT* context,
    unsigned long access,
    const void* accessed
) noexcept {
    char line[line_capacity] = {};
    char* const end = line + sizeof(line) - 2;
    char* at = put_text(line, end, "--- ");
    at = put_text(at, end, kind);
    at = put_text(at, end, " code=");
    at = put_hex(at, end, code, 8);
    at = put_text(at, end, " at=");
    at = put_hex(at, end, reinterpret_cast<unsigned long>(where), 8);
    at = put_text(at, end, " eip=");
    at = put_hex(at, end, context != nullptr ? context->Eip : 0, 8);
    at = put_text(at, end, " esp=");
    at = put_hex(at, end, context != nullptr ? context->Esp : 0, 8);
    at = put_text(at, end, " ebp=");
    at = put_hex(at, end, context != nullptr ? context->Ebp : 0, 8);
    if (access != 0 || accessed != nullptr) {
        at = put_text(at, end, " fault=");
        at = put_hex(at, end, reinterpret_cast<unsigned long>(accessed), 8);
        // Zero is a read, one a write, eight a fetch that the page would not
        // allow — the three an access violation reports.
        at = put_text(at, end, access == 1 ? " write" : (access == 8 ? " execute" : " read"));
    }
    at = put_text(at, end, " thread=");
    at = put_dec(at, end, GetCurrentThreadId());
    *at++ = '\n';

    const char* const base = reinterpret_cast<const char*>(GetModuleHandleA(nullptr));
    unsigned long size = 0;
    if (base != nullptr) {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        size = nt->OptionalHeader.SizeOfImage;
    }
    at = put_text(at, end, "image base=");
    at = put_hex(at, end, reinterpret_cast<unsigned long>(base), 8);
    at = put_text(at, end, " size=");
    at = put_hex(at, end, size, 8);
    *at++ = '\n';

    HANDLE file = open_report();
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD reason = GetLastError();
        char failure[128] = {};
        char* out = put_text(failure, failure + sizeof(failure) - 1, "open-annihilation: no report, error ");
        out = put_dec(out, failure + sizeof(failure) - 1, reason);
        *out++ = '\n';
        std::fwrite(failure, 1, static_cast<std::size_t>(out - failure), stderr);
        std::fflush(stderr);
    } else {
        append(file, line, static_cast<std::size_t>(at - line));
    }

    std::fwrite(line, 1, static_cast<std::size_t>(at - line), stderr);
    std::fflush(stderr);

    // The frames: from the faulting thread's own stack pointer when there is
    // one, so what is read are the program's return addresses, and otherwise
    // from this frame's base, which sits above the buffer this function holds.
    //
    // The stack pointer and not the frame base: the base was tried first and
    // the scan then stopped at once, reporting no frame at all, so the value
    // cannot be relied on from a context record here. Starting lower and
    // crossing the faulting function's own locals costs a few words and always
    // reads something.
    unsigned long read = 0;
    if (context != nullptr && context->Esp != 0)
        read = write_frames(file, reinterpret_cast<const unsigned long*>(context->Esp));
    else
        read = write_frames(
            file, reinterpret_cast<const unsigned long*>(__builtin_frame_address(0))
        );
    if (file != INVALID_HANDLE_VALUE) {
        // How far the scan got, so an empty frame list says why it is empty.
        char scanned[32] = {};
        char* out = put_text(scanned, scanned + sizeof(scanned) - 2, "scanned ");
        out = put_dec(out, scanned + sizeof(scanned) - 2, read);
        *out++ = '\n';
        append(file, scanned, static_cast<std::size_t>(out - scanned));
        CloseHandle(file);
    }
}

void on_signal(int number) noexcept {
    write_stop("signal", static_cast<unsigned long>(number), nullptr, nullptr, 0, nullptr);
    _exit(3);
}

/// Records a fault that nothing handled, with what it was doing.
///
/// The vectored handler above is the natural place for this and does nothing
/// on Windows 95: AddVectoredExceptionHandler is not there, and the stand-in
/// for it returns a token without installing anything — the same silent no-op
/// as the wide API. An access violation is unhandled by definition, so this
/// filter sees it, and it carries the registers and the fault's own parameters.
///
/// @param info the exception and the registers that were running
/// @return to terminate, since the fault was not handled by anyone
LONG WINAPI on_unhandled(EXCEPTION_POINTERS* info) noexcept {
    unsigned long code = 0;
    const void* at = nullptr;
    const void* accessed = nullptr;
    unsigned long access = 0;
    if (info != nullptr && info->ExceptionRecord != nullptr) {
        code = info->ExceptionRecord->ExceptionCode;
        at = info->ExceptionRecord->ExceptionAddress;
        // An access violation is the one that says what it was doing: whether
        // the fault was a read or a write, and at which address.
        if (info->ExceptionRecord->NumberParameters >= 2) {
            access = info->ExceptionRecord->ExceptionInformation[0];
            accessed =
                reinterpret_cast<const void*>(info->ExceptionRecord->ExceptionInformation[1]);
        }
    }
    write_stop(
        "unhandled", code, at, info != nullptr ? info->ContextRecord : nullptr, access, accessed
    );
    return EXCEPTION_EXECUTE_HANDLER;
}

/// Records a fault where it is raised, when the system can raise it.
///
/// A vectored handler runs first, on the faulting thread, with the registers
/// and the stack exactly as the fault left them. **It never runs on Windows
/// 95**: AddVectoredExceptionHandler is not there, and the stand-in for it
/// returns the handler as a token without installing anything, so this is dead
/// code on the machine it was written for and the unhandled filter below is
/// what reports a fault there. Kept because it costs nothing and does work on
/// the later Windows the same binary runs on.
///
/// @param info the exception and the registers that were running
/// @return always to keep searching, so the normal handling still happens
LONG WINAPI on_fault(EXCEPTION_POINTERS* info) noexcept {
    if (info == nullptr || info->ExceptionRecord == nullptr)
        return EXCEPTION_CONTINUE_SEARCH;
    const unsigned long code = info->ExceptionRecord->ExceptionCode;
    // The run time uses exceptions for ordinary control flow: every C++ throw
    // arrives here too, as do the debugger's codes and the thread-naming one.
    // Only a real fault — the error severity, and not the C++ throw — is
    // recorded, or the report would be nothing but the program working.
    if (code < 0xC0000000UL || code == 0xE06D7363UL)
        return EXCEPTION_CONTINUE_SEARCH;
    // A fault inside this record would arrive here again, and then again: the
    // second is left to the normal handling.
    if (InterlockedExchange(&recording, 1) != 0)
        return EXCEPTION_CONTINUE_SEARCH;
    const void* accessed = nullptr;
    unsigned long access = 0;
    if (info->ExceptionRecord->NumberParameters >= 2) {
        access = info->ExceptionRecord->ExceptionInformation[0];
        accessed = reinterpret_cast<const void*>(info->ExceptionRecord->ExceptionInformation[1]);
    } else {
        accessed = info->ExceptionRecord->ExceptionAddress;
    }
    write_stop(
        "fault", code, info->ExceptionRecord->ExceptionAddress, info->ContextRecord, access, accessed
    );
    InterlockedExchange(&recording, 0);
    return EXCEPTION_CONTINUE_SEARCH;
}

/// Installs the traps that need installing, before any C++ static initialiser
/// runs, because the stop may be one of those.
__attribute__((constructor(101))) void install_stop_reporting() {
    std::signal(SIGABRT, on_signal);
    SetUnhandledExceptionFilter(on_unhandled);
    // Does nothing on Windows 95, where the call is a stand-in: see on_fault.
    AddVectoredExceptionHandler(1, on_fault);
}

} // namespace

// The abort every caller in the program reaches, taken over.
//
// Nothing in the program calls the system's abort by that name afterwards: the
// definition here is what the import library's placeholder would have been, so
// the calls that would have gone to the system arrive here first. The system's
// own is looked up by hand afterwards, and ends the process as it would have.

extern "C" void oa_stop_abort() __asm__("_abort");
extern "C" void oa_stop_abort() {
    // Where this abort was reached from: the one address that names the call
    // that stopped the process, taken rather than searched for.
    write_stop("abort", 0, __builtin_return_address(0), nullptr, 0, nullptr);
    using AbortFunction = void (*)();
    const HMODULE crt = GetModuleHandleA("msvcrt20.dll");
    if (crt != nullptr) {
        const auto system = reinterpret_cast<AbortFunction>(GetProcAddress(crt, "abort"));
        if (system != nullptr && system != &oa_stop_abort)
            system();
    }
    _exit(3);
}

extern "C" constinit decltype(&oa_stop_abort) const oa_stop_abort_import __asm__("__imp__abort") =
    &oa_stop_abort;

// Every C++ exception, taken at the throw rather than at the abort.
//
// The unwinder aborts before any handler runs on this machine, so the catch in
// main never sees the exception and the message it carries is lost. This reads
// the exception where it is still whole — its type, and the text it carries —
// and then throws it exactly as the program meant to.
//
// Reached through --wrap, so the call sites in the run time come here and the
// real one is still callable.

extern "C" void __real___cxa_throw(void* thrown, std::type_info* kind, void (*destruct)(void*));

extern "C" void __wrap___cxa_throw(void* thrown, std::type_info* kind, void (*destruct)(void*)) {
    HANDLE file = open_report();
    char line[line_capacity] = {};
    char* const end = line + sizeof(line) - 2;
    char* at = line;
    if (kind != nullptr) {
        at = put_text(at, end, "--- thrown: ");
        at = put_text(at, end, kind->name());
        *at++ = '\n';
    }
    // A thrown object derived from std::exception carries the text a caller
    // would have printed had it been given the chance. Anything else is left to
    // the type name above.
    const char* text = nullptr;
    if (kind != nullptr) {
        const bool exception_type = std::strstr(kind->name(), "Exception") != nullptr
                                    || std::strstr(kind->name(), "error") != nullptr;
        if (exception_type)
            text = static_cast<const std::exception*>(thrown)->what();
    }
    if (text != nullptr) {
        at = put_text(at, end, "text: ");
        at = put_text(at, end, text);
        *at++ = '\n';
    } else if (kind != nullptr) {
        at = put_text(at, end, "text: (none)\n");
    }
    if (file != INVALID_HANDLE_VALUE) {
        append(file, line, static_cast<std::size_t>(at - line));
        // Where the throw came from: the frames above this wrapper's own, which
        // is what names the call that could not find what it wanted.
        write_frames(file, reinterpret_cast<const unsigned long*>(__builtin_frame_address(0)));
        CloseHandle(file);
    }
    std::fwrite(line, 1, static_cast<std::size_t>(at - line), stderr);
    std::fflush(stderr);
    __real___cxa_throw(thrown, kind, destruct);
}
