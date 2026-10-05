# SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
# SPDX-License-Identifier: GPL-3.0-only

# The functions that Windows XP lacks and the C++ run-time library calls:
# slim locks, condition variables and one-time initialisation on every
# system (where they are tested), and with MinGW the definitions under the
# names programs import them by, which cmake/OaWindowsXp.cmake links into
# every executable of an OA_WINDOWS_XP build.
add_library(oa-platform-xp-runtime src/slim_sync.cpp)
add_library(oa::platform::xp_runtime ALIAS oa-platform-xp-runtime)
target_include_directories(oa-platform-xp-runtime PUBLIC include)
target_compile_features(oa-platform-xp-runtime PUBLIC cxx_std_20)
target_link_libraries(oa-platform-xp-runtime PRIVATE oa-base-threads oa-options)
if(MINGW)
  target_sources(oa-platform-xp-runtime PRIVATE src/windows_functions.cpp)
  target_link_libraries(oa-platform-xp-runtime PRIVATE psapi)
endif()

# The functions Windows 95 lacks that the C++ run-time library and SDL call,
# which the file above's counterparts cover for Windows XP. They are objects of
# the program rather than a library on the link line: an import library SDL
# names is linked before any library of ours, so a function SDL calls has
# already been linked from it by the time ours arrives, and a second definition
# is what the linker sees rather than a replacement. An object of the program
# is linked before all of them. The functions the file above stands in for are
# ones only the C++ run-time library calls, which is linked last, so a library
# suits those.
if(MINGW AND OA_WINDOWS_95)
  add_library(
    oa-platform-win95-runtime OBJECT src/windows_95_kernel.cpp src/windows_95_user.cpp
                                         src/windows_95_shell.cpp
  )
  add_library(oa::platform::win95_runtime ALIAS oa-platform-win95-runtime)
  target_include_directories(oa-platform-win95-runtime PUBLIC include)
  target_compile_features(oa-platform-win95-runtime PUBLIC cxx_std_20)
  target_link_libraries(oa-platform-win95-runtime PRIVATE oa-options)
  target_link_libraries(
    oa-options INTERFACE
    "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:$<TARGET_OBJECTS:oa-platform-win95-runtime>>"
  )
endif()

if(BUILD_TESTING)
  add_executable(oa-platform-xp-runtime-test tests/xp_runtime_test.cpp)
  target_link_libraries(oa-platform-xp-runtime-test PRIVATE oa-platform-xp-runtime oa-base-threads)
  add_test(NAME platform-xp-runtime COMMAND oa-platform-xp-runtime-test)
  set_tests_properties(platform-xp-runtime PROPERTIES TIMEOUT 60)
endif()
