// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

// The user32 functions Windows 95 does not export, defined under the names a
// program imports them by, so that a program linked with this file imports
// none of them: Windows refuses to start one that imports a function its
// system DLLs do not export. Each call looks the system's own function up and
// uses it where the running Windows has it — Windows 98, 2000 and XP have most
// of these, some of them better than a stand-in can — and stands in where it
// does not. Built only for MinGW, whose import naming it follows, and beside
// windows_functions.cpp, whose macros and system lookup this file repeats
// because they are private to it.

#include "oa/platform/xp_runtime.hpp"

// The C++ standard headers come first, before the Windows 95 declarations are
// pinned below: they reach the toolchain's thread support, whose condition
// variables a win32-threaded toolchain declares for the version this file is
// compiled at, not for Windows 95.
#include <atomic>
#include <cstddef>

// The declarations of Windows 95, so that none of the functions defined here
// is also declared as the system's.
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#undef WINVER
#define WINVER 0x0400
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// The symbol a function is defined by, and the import pointer a program calls
// it through, in MinGW's naming; see windows_functions.cpp, which defines the
// same four.
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
/// The lookup gives every thread the same answer, so threads that look it up
/// at the same time agree; the result is kept in atomics, which need no code
/// to initialise them.
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

constexpr wchar_t user32[] = L"user32.dll";
constexpr wchar_t comctl32[] = L"comctl32.dll";

/// The one display a Windows 95 machine can drive, and the monitor on it.
///
/// No call makes such a monitor handle, so the stand-ins hand out this word
/// where a Windows 95 machine has a single monitor and recognise it again.
constexpr ULONG_PTR single_monitor = 1;

constexpr wchar_t primary_display[] = L"\\\\.\\DISPLAY1";

/// Copies a wide string into a fixed-size array of the Windows API's fields,
/// ending it and never writing past the array.
template <std::size_t Size>
void copy_wide(wchar_t (&out)[Size], const wchar_t* text) noexcept {
    std::size_t index = 0;
    for (; index + 1 < Size && text[index] != L'\0'; ++index)
        out[index] = text[index];
    out[index] = L'\0';
}

using AllowSetForegroundFunction = BOOL(WINAPI*)(DWORD);
using ChangeDisplaySettingsFunction =
    LONG(WINAPI*)(LPCWSTR, LPDEVMODEW, HWND, DWORD, LPVOID);
using EnumDisplayDevicesFunction = BOOL(WINAPI*)(LPCWSTR, DWORD, PDISPLAY_DEVICEW, DWORD);
using EnumDisplayMonitorsFunction = BOOL(WINAPI*)(HDC, LPCRECT, MONITORENUMPROC, LPARAM);
using FlashWindowFunction = BOOL(WINAPI*)(PFLASHWINFO);
using ClipboardSequenceFunction = DWORD(WINAPI*)(void);
using MonitorInfoFunction = BOOL(WINAPI*)(HMONITOR, LPMONITORINFO);
using MonitorFromPointFunction = HMONITOR(WINAPI*)(POINT, DWORD);
using MonitorFromWindowFunction = HMONITOR(WINAPI*)(HWND, DWORD);
using DeviceNotificationFunction = HDEVNOTIFY(WINAPI*)(HANDLE, LPVOID, DWORD);
using DropDeviceNotificationFunction = BOOL(WINAPI*)(HDEVNOTIFY);
using RawInputListFunction = UINT(WINAPI*)(PRAWINPUTDEVICELIST, PUINT, UINT);
using RawInputDeviceInfoFunction = UINT(WINAPI*)(HANDLE, UINT, LPVOID, PUINT);
using RawInputDataFunction = UINT(WINAPI*)(HRAWINPUT, UINT, LPVOID, PUINT, UINT);
using RawInputBufferFunction = UINT(WINAPI*)(PRAWINPUT, PUINT, UINT);
using RegisterRawInputFunction = BOOL(WINAPI*)(PCRAWINPUTDEVICE, UINT, UINT);
using LayeredWindowFunction = BOOL(WINAPI*)(HWND, COLORREF, BYTE, DWORD);
using TrackMouseFunction = BOOL(WINAPI*)(LPTRACKMOUSEEVENT);

constinit SystemFunction<AllowSetForegroundFunction> system_allow_set_foreground{
    user32, "AllowSetForegroundWindow"
};
constinit SystemFunction<ChangeDisplaySettingsFunction> system_change_display_settings{
    user32, "ChangeDisplaySettingsExW"
};
constinit SystemFunction<EnumDisplayDevicesFunction> system_enum_display_devices{
    user32, "EnumDisplayDevicesW"
};
constinit SystemFunction<EnumDisplayMonitorsFunction> system_enum_display_monitors{
    user32, "EnumDisplayMonitors"
};
constinit SystemFunction<FlashWindowFunction> system_flash_window{user32, "FlashWindowEx"};
constinit SystemFunction<ClipboardSequenceFunction> system_clipboard_sequence{
    user32, "GetClipboardSequenceNumber"
};
constinit SystemFunction<MonitorInfoFunction> system_monitor_info{user32, "GetMonitorInfoW"};
constinit SystemFunction<RawInputBufferFunction> system_raw_input_buffer{
    user32, "GetRawInputBuffer"
};
constinit SystemFunction<RawInputDataFunction> system_raw_input_data{user32, "GetRawInputData"};
constinit SystemFunction<RawInputDeviceInfoFunction> system_raw_input_device_info{
    user32, "GetRawInputDeviceInfoA"
};
constinit SystemFunction<RawInputListFunction> system_raw_input_device_list{
    user32, "GetRawInputDeviceList"
};
constinit SystemFunction<MonitorFromPointFunction> system_monitor_from_point{
    user32, "MonitorFromPoint"
};
constinit SystemFunction<MonitorFromWindowFunction> system_monitor_from_window{
    user32, "MonitorFromWindow"
};
constinit SystemFunction<DeviceNotificationFunction> system_register_device_notification{
    user32, "RegisterDeviceNotificationW"
};
constinit SystemFunction<RegisterRawInputFunction> system_register_raw_input{
    user32, "RegisterRawInputDevices"
};
constinit SystemFunction<LayeredWindowFunction> system_layered_window{
    user32, "SetLayeredWindowAttributes"
};
constinit SystemFunction<TrackMouseFunction> system_track_mouse{user32, "TrackMouseEvent"};
constinit SystemFunction<DropDeviceNotificationFunction> system_unregister_device_notification{
    user32, "UnregisterDeviceNotification"
};
// Windows 95 and NT 4 keep TrackMouseEvent in the common controls library,
// under a name with a leading underscore, and a program built for Windows 95
// has no other reason to have loaded that library, so the lookup loads it.
std::atomic<TrackMouseFunction> common_controls_track_mouse{};
std::atomic<bool> common_controls_looked_up{};

/// Finds Windows 95's own TrackMouseEvent.
///
/// The library is loaded for the lookup and stays loaded, as one the system
/// has loaded itself would.
///
/// @return the common controls library's TrackMouseEvent, or null when it
/// cannot be had
TrackMouseFunction find_common_controls_track_mouse() noexcept {
    if (!common_controls_looked_up.load(std::memory_order_acquire)) {
        TrackMouseFunction found = nullptr;
        if (const HMODULE library = LoadLibraryW(comctl32)) {
            found = reinterpret_cast<TrackMouseFunction>(
                reinterpret_cast<void*>(GetProcAddress(library, "_TrackMouseEvent"))
            );
        }
        common_controls_track_mouse.store(found, std::memory_order_relaxed);
        common_controls_looked_up.store(true, std::memory_order_release);
    }
    return common_controls_track_mouse.load(std::memory_order_relaxed);
}

/// The display's rectangle in its own pixels.
RECT screen_rectangle() noexcept {
    RECT rectangle{};
    rectangle.right = GetSystemMetrics(SM_CXSCREEN);
    rectangle.bottom = GetSystemMetrics(SM_CYSCREEN);
    return rectangle;
}

/// Whether a point lies on the display.
bool on_screen(POINT point) noexcept {
    const RECT screen = screen_rectangle();
    return point.x >= screen.left && point.x < screen.right && point.y >= screen.top &&
           point.y < screen.bottom;
}

/// The monitor the Windows API's default flags name for a place that is off
/// every display: the primary one unless the caller asked for none.
HMONITOR fall_back_monitor(DWORD flags) noexcept {
    if (flags == MONITOR_DEFAULTTONULL)
        return nullptr;
    return reinterpret_cast<HMONITOR>(single_monitor);
}

} // namespace

/// Lets another process bring its window forward.
///
/// Windows 95 has no such permission to grant: a process it starts may come
/// forward without asking, so the stand-in reports that it may.
extern "C" BOOL WINAPI
allow_set_foreground_window(DWORD process_id) __asm__(
    OA_XP_SYSTEM_SYMBOL(AllowSetForegroundWindow, 4)
);

BOOL WINAPI allow_set_foreground_window(DWORD process_id) {
    if (const auto system = system_allow_set_foreground.get())
        return system(process_id);
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(allow_set_foreground_window, AllowSetForegroundWindow, 4);

/// Changes the display's mode.
///
/// Windows 95 has one display and the older call, which takes the mode's
/// numbers without naming the display: the stand-in passes the four fields a
/// mode is set from on, and any other display name fails as an unknown mode.
extern "C" LONG WINAPI change_display_settings_ex(
    LPCWSTR device_name, LPDEVMODEW mode, HWND window, DWORD flags, LPVOID parameter
) __asm__(OA_XP_SYSTEM_SYMBOL(ChangeDisplaySettingsExW, 20));

LONG WINAPI change_display_settings_ex(
    LPCWSTR device_name, LPDEVMODEW mode, HWND window, DWORD flags, LPVOID parameter
) {
    if (const auto system = system_change_display_settings.get())
        return system(device_name, mode, window, flags, parameter);
    (void)window;
    (void)parameter;
    if (device_name != nullptr && device_name[0] != L'\0' &&
        lstrcmpiW(device_name, primary_display) != 0)
        return DISP_CHANGE_BADMODE;
    if (mode == nullptr)
        return ChangeDisplaySettingsA(nullptr, flags);
    DEVMODEA wanted{};
    wanted.dmSize = sizeof(wanted);
    wanted.dmFields =
        mode->dmFields & (DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY
                          | DM_DISPLAYFLAGS);
    if ((wanted.dmFields & DM_BITSPERPEL) != 0)
        wanted.dmBitsPerPel = mode->dmBitsPerPel;
    if ((wanted.dmFields & DM_PELSWIDTH) != 0)
        wanted.dmPelsWidth = mode->dmPelsWidth;
    if ((wanted.dmFields & DM_PELSHEIGHT) != 0)
        wanted.dmPelsHeight = mode->dmPelsHeight;
    if ((wanted.dmFields & DM_DISPLAYFREQUENCY) != 0)
        wanted.dmDisplayFrequency = mode->dmDisplayFrequency;
    if ((wanted.dmFields & DM_DISPLAYFLAGS) != 0)
        wanted.dmDisplayFlags = mode->dmDisplayFlags;
    return ChangeDisplaySettingsA(&wanted, flags);
}

OA_XP_DEFINE_SYSTEM(change_display_settings_ex, ChangeDisplaySettingsExW, 20);

/// Describes a display device.
///
/// Windows 95 drives one display, and enumeration names it. Asking about a
/// display by name asks about that one display's monitors, which 95 does not
/// report, so only the display itself is described.
extern "C" BOOL WINAPI enum_display_devices(
    LPCWSTR device, DWORD number, PDISPLAY_DEVICEW information, DWORD flags
) __asm__(OA_XP_SYSTEM_SYMBOL(EnumDisplayDevicesW, 16));

BOOL WINAPI
enum_display_devices(LPCWSTR device, DWORD number, PDISPLAY_DEVICEW information, DWORD flags) {
    if (const auto system = system_enum_display_devices.get())
        return system(device, number, information, flags);
    if (information == nullptr || number != 0 || (device != nullptr && device[0] != L'\0'))
        return FALSE;
    information->cb = sizeof(*information);
    copy_wide(information->DeviceName, primary_display);
    copy_wide(information->DeviceString, L"Primary Display");
    information->StateFlags = DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE |
                              DISPLAY_DEVICE_VGA_COMPATIBLE;
    information->DeviceID[0] = L'\0';
    information->DeviceKey[0] = L'\0';
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(enum_display_devices, EnumDisplayDevicesW, 16);

/// Calls back once for the monitor a Windows 95 machine has.
///
/// The handle handed to the callback is the one the other stand-ins here
/// recognise, so it can be passed to them as a Windows monitor handle is.
extern "C" BOOL WINAPI enum_display_monitors(
    HDC device_context, LPCRECT clip, MONITORENUMPROC callback, LPARAM data
) __asm__(OA_XP_SYSTEM_SYMBOL(EnumDisplayMonitors, 16));

BOOL WINAPI enum_display_monitors(
    HDC device_context, LPCRECT clip, MONITORENUMPROC callback, LPARAM data
) {
    if (const auto system = system_enum_display_monitors.get())
        return system(device_context, clip, callback, data);
    (void)clip;
    if (callback == nullptr)
        return FALSE;
    RECT screen = screen_rectangle();
    HDC monitor_context = device_context;
    bool made_context = false;
    if (monitor_context == nullptr) {
        monitor_context = GetDC(nullptr);
        made_context = true;
    }
    callback(reinterpret_cast<HMONITOR>(single_monitor), monitor_context, &screen, data);
    if (made_context)
        ReleaseDC(nullptr, monitor_context);
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(enum_display_monitors, EnumDisplayMonitors, 16);

/// Flashes a window's caption or its taskbar button.
///
/// Windows 95 has the older call, which inverts the window's flash state
/// rather than naming the parts to flash: the stand-in inverts unless the
/// caller asked for the flashing to stop.
extern "C" BOOL WINAPI flash_window_ex(PFLASHWINFO information) __asm__(
    OA_XP_SYSTEM_SYMBOL(FlashWindowEx, 4)
);

BOOL WINAPI flash_window_ex(PFLASHWINFO information) {
    if (const auto system = system_flash_window.get())
        return system(information);
    if (information == nullptr)
        return FALSE;
    return FlashWindow(information->hwnd, (information->dwFlags & FLASHW_STOP) == 0);
}

OA_XP_DEFINE_SYSTEM(flash_window_ex, FlashWindowEx, 4);

/// Returns a number that changes when the clipboard does.
///
/// Windows 95 does not count the clipboard's changes and tells no program
/// when it changes, so the stand-in reports no change at all.
extern "C" DWORD WINAPI get_clipboard_sequence_number(void) __asm__(
    OA_XP_SYSTEM_SYMBOL(GetClipboardSequenceNumber, 0)
);

DWORD WINAPI get_clipboard_sequence_number(void) {
    if (const auto system = system_clipboard_sequence.get())
        return system();
    return 0;
}

OA_XP_DEFINE_SYSTEM(get_clipboard_sequence_number, GetClipboardSequenceNumber, 0);

/// Fills in what Windows 95 knows of the display its monitor handle names.
///
/// There is one display, so every handle the stand-ins here hand out names
/// it: its rectangle, the desktop's work area as Windows reserves it, and the
/// display name a monitor handle is asked about by.
extern "C" BOOL WINAPI get_monitor_info(HMONITOR monitor, LPMONITORINFO information) __asm__(
    OA_XP_SYSTEM_SYMBOL(GetMonitorInfoW, 8)
);

BOOL WINAPI get_monitor_info(HMONITOR monitor, LPMONITORINFO information) {
    if (const auto system = system_monitor_info.get())
        return system(monitor, information);
    if (monitor == nullptr || information == nullptr || information->cbSize < sizeof(MONITORINFO)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    information->rcMonitor = screen_rectangle();
    information->rcWork = information->rcMonitor;
    RECT work{};
    if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0))
        information->rcWork = work;
    information->dwFlags = MONITORINFOF_PRIMARY;
    if (information->cbSize >= sizeof(MONITORINFOEXW))
        copy_wide(
            reinterpret_cast<LPMONITORINFOEXW>(information)->szDevice, primary_display
        );
    return TRUE;
}

OA_XP_DEFINE_SYSTEM(get_monitor_info, GetMonitorInfoW, 8);

/// Reads raw input, which Windows 95 does not have.
///
/// Nothing on Windows 95 delivers raw input; a program that asks for it gets
/// the failure the call gives when no such input is there, and reads its
/// input from the window messages it is sent instead.
extern "C" UINT WINAPI get_raw_input_buffer(
    PRAWINPUT buffer, PUINT count, UINT header_size
) __asm__(OA_XP_SYSTEM_SYMBOL(GetRawInputBuffer, 12));

UINT WINAPI get_raw_input_buffer(PRAWINPUT buffer, PUINT count, UINT header_size) {
    if (const auto system = system_raw_input_buffer.get())
        return system(buffer, count, header_size);
    (void)buffer;
    (void)count;
    (void)header_size;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return static_cast<UINT>(-1);
}

OA_XP_DEFINE_SYSTEM(get_raw_input_buffer, GetRawInputBuffer, 12);

/// Reads one raw input message, which Windows 95 does not have.
extern "C" UINT WINAPI get_raw_input_data(
    HRAWINPUT input, UINT command, LPVOID data, PUINT size, UINT header_size
) __asm__(OA_XP_SYSTEM_SYMBOL(GetRawInputData, 20));

UINT WINAPI
get_raw_input_data(HRAWINPUT input, UINT command, LPVOID data, PUINT size, UINT header_size) {
    if (const auto system = system_raw_input_data.get())
        return system(input, command, data, size, header_size);
    (void)input;
    (void)command;
    (void)data;
    (void)size;
    (void)header_size;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return static_cast<UINT>(-1);
}

OA_XP_DEFINE_SYSTEM(get_raw_input_data, GetRawInputData, 20);

/// Describes a raw input device, which Windows 95 does not have.
extern "C" UINT WINAPI get_raw_input_device_info(
    HANDLE device, UINT command, LPVOID data, PUINT size
) __asm__(OA_XP_SYSTEM_SYMBOL(GetRawInputDeviceInfoA, 16));

UINT WINAPI get_raw_input_device_info(HANDLE device, UINT command, LPVOID data, PUINT size) {
    if (const auto system = system_raw_input_device_info.get())
        return system(device, command, data, size);
    (void)device;
    (void)command;
    (void)data;
    (void)size;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return static_cast<UINT>(-1);
}

OA_XP_DEFINE_SYSTEM(get_raw_input_device_info, GetRawInputDeviceInfoA, 16);

/// Lists the raw input devices, of which Windows 95 has none.
extern "C" UINT WINAPI get_raw_input_device_list(
    PRAWINPUTDEVICELIST devices, PUINT count, UINT size
) __asm__(OA_XP_SYSTEM_SYMBOL(GetRawInputDeviceList, 12));

UINT WINAPI get_raw_input_device_list(PRAWINPUTDEVICELIST devices, PUINT count, UINT size) {
    if (const auto system = system_raw_input_device_list.get())
        return system(devices, count, size);
    (void)devices;
    (void)count;
    (void)size;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return static_cast<UINT>(-1);
}

OA_XP_DEFINE_SYSTEM(get_raw_input_device_list, GetRawInputDeviceList, 12);

/// Names the monitor a point lies on.
///
/// Windows 95 has one monitor, so a point on the display names it and a point
/// off the display names it too unless the caller asked for none.
extern "C" HMONITOR WINAPI monitor_from_point(POINT point, DWORD flags) __asm__(
    OA_XP_SYSTEM_SYMBOL(MonitorFromPoint, 12)
);

HMONITOR WINAPI monitor_from_point(POINT point, DWORD flags) {
    if (const auto system = system_monitor_from_point.get())
        return system(point, flags);
    if (on_screen(point))
        return reinterpret_cast<HMONITOR>(single_monitor);
    return fall_back_monitor(flags);
}

OA_XP_DEFINE_SYSTEM(monitor_from_point, MonitorFromPoint, 12);

/// Names the monitor a window is on.
///
/// Windows 95 has one monitor, so a window names it, and a window there is
/// none of is treated as a point off the display is.
extern "C" HMONITOR WINAPI monitor_from_window(HWND window, DWORD flags) __asm__(
    OA_XP_SYSTEM_SYMBOL(MonitorFromWindow, 8)
);

HMONITOR WINAPI monitor_from_window(HWND window, DWORD flags) {
    if (const auto system = system_monitor_from_window.get())
        return system(window, flags);
    if (window == nullptr && flags == MONITOR_DEFAULTTONULL)
        return nullptr;
    return reinterpret_cast<HMONITOR>(single_monitor);
}

OA_XP_DEFINE_SYSTEM(monitor_from_window, MonitorFromWindow, 8);

/// Asks to be told of a device's comings and goings, which Windows 95 does
/// not report.
extern "C" HDEVNOTIFY WINAPI register_device_notification(
    HANDLE recipient, LPVOID filter, DWORD flags
) __asm__(OA_XP_SYSTEM_SYMBOL(RegisterDeviceNotificationW, 12));

HDEVNOTIFY WINAPI register_device_notification(HANDLE recipient, LPVOID filter, DWORD flags) {
    if (const auto system = system_register_device_notification.get())
        return system(recipient, filter, flags);
    (void)recipient;
    (void)filter;
    (void)flags;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return nullptr;
}

OA_XP_DEFINE_SYSTEM(register_device_notification, RegisterDeviceNotificationW, 12);

/// Asks for raw input, which Windows 95 does not have.
extern "C" BOOL WINAPI register_raw_input_devices(
    PCRAWINPUTDEVICE devices, UINT count, UINT size
) __asm__(OA_XP_SYSTEM_SYMBOL(RegisterRawInputDevices, 12));

BOOL WINAPI register_raw_input_devices(PCRAWINPUTDEVICE devices, UINT count, UINT size) {
    if (const auto system = system_register_raw_input.get())
        return system(devices, count, size);
    (void)devices;
    (void)count;
    (void)size;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(register_raw_input_devices, RegisterRawInputDevices, 12);

/// Sets how much of a window shows through, which Windows 95 windows cannot.
extern "C" BOOL WINAPI set_layered_window_attributes(
    HWND window, COLORREF key, BYTE alpha, DWORD flags
) __asm__(OA_XP_SYSTEM_SYMBOL(SetLayeredWindowAttributes, 16));

BOOL WINAPI set_layered_window_attributes(HWND window, COLORREF key, BYTE alpha, DWORD flags) {
    if (const auto system = system_layered_window.get())
        return system(window, key, alpha, flags);
    (void)window;
    (void)key;
    (void)alpha;
    (void)flags;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(set_layered_window_attributes, SetLayeredWindowAttributes, 16);

/// Asks to be told when the pointer leaves or rests on a window.
///
/// Windows 95 keeps this call in its common controls library, under a name
/// with a leading underscore, where the system has no such export of its own.
extern "C" BOOL WINAPI track_mouse_event(LPTRACKMOUSEEVENT event) __asm__(
    OA_XP_SYSTEM_SYMBOL(TrackMouseEvent, 4)
);

BOOL WINAPI track_mouse_event(LPTRACKMOUSEEVENT event) {
    if (const auto system = system_track_mouse.get())
        return system(event);
    if (const auto common_controls = find_common_controls_track_mouse())
        return common_controls(event);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(track_mouse_event, TrackMouseEvent, 4);

/// Stops being told of a device's comings and goings, which Windows 95 never
/// reported.
extern "C" BOOL WINAPI unregister_device_notification(HDEVNOTIFY notification) __asm__(
    OA_XP_SYSTEM_SYMBOL(UnregisterDeviceNotification, 4)
);

BOOL WINAPI unregister_device_notification(HDEVNOTIFY notification) {
    if (const auto system = system_unregister_device_notification.get())
        return system(notification);
    (void)notification;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

OA_XP_DEFINE_SYSTEM(unregister_device_notification, UnregisterDeviceNotification, 4);
