# SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
# SPDX-License-Identifier: GPL-3.0-only

# A 32-bit mingw-w64 toolchain whose C++ run-time library uses the Windows
# thread backend, for building the executables cmake/OaWindows95.cmake makes.
#
# nixpkgs' mingw-w64 is built with --enable-threads=mcf, and mcfgthread imports
# ntdll's keyed events (NtCreateSection, NtWaitForKeyedEvent and so on).
# Windows 95 has no ntdll at all, so a program linked against that run-time
# library cannot load there whatever else it avoids. Rebuilding the C++ run-time
# library with the "win32" backend drops the import.
#
#   nix-shell tools/win95-mingw32.nix
#
# gives a shell whose i686-w64-mingw32-gcc is that toolchain; configure CMake
# inside it with cmake/toolchains/i686-w64-mingw32.cmake -DOA_WINDOWS_95=ON.
{ nixpkgs ? import <nixpkgs> { } }:
let
  pkgs = nixpkgs.pkgsCross.mingw32;

  # The backend is chosen by a configure option of the compiler the C++ run-time
  # library is built with, so the whole compiler is rebuilt with it changed.
  win32Crt = pkgs.stdenv.cc.cc.overrideAttrs (old: {
    configureFlags =
      map (flag: if flag == "--enable-threads=mcf" then "--enable-threads=win32" else flag)
        old.configureFlags;
  });

  stdenv = pkgs.stdenv.override {
    cc = pkgs.stdenv.cc.override { cc = win32Crt; };
  };
in
nixpkgs.mkShell {
  packages = [
    stdenv.cc
    nixpkgs.cmake
    nixpkgs.ninja
    nixpkgs.python3
    nixpkgs.pkg-config
  ];
}
