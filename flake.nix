{
  description = "Open Annihilation: the engine, and its Windows 95 build";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/b1b875982b17dabde9b4a37f3e229e74913e6db3";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      # The Windows 95 build is a cross-compilation from a Linux host: the
      # toolchain overlay rebuilds pkgsCross.mingw32, which is a Linux cross
      # set, so offering it elsewhere would put an attribute in the flake that
      # cannot evaluate.
      linuxSystems = [ "x86_64-linux" "aarch64-linux" ];

      # The toolchain overlay goes on every set. It changes nothing where the
      # target is not MinGW, which is what lets the Windows 95 build come out
      # of pkgsCross rather than out of a stdenv passed around by hand.
      mkPkgs = system:
        import nixpkgs {
          inherit system;
          overlays = [ (import ./nix/win95-toolchain.nix) ];
        };

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (mkPkgs system));
      forLinuxSystems = f: nixpkgs.lib.genAttrs linuxSystems (system: f (mkPkgs system));

      # The engine as this system builds it. Its source is this tree, so what is
      # built is what is checked out rather than a release fetched from GitHub.
      linux = pkgs: pkgs.callPackage ./nix/linux.nix { src = self; };

      # The Windows 95 build: the same tree, cross-compiled for that system.
      win95 = pkgs:
        let
          cross = pkgs.pkgsCross.mingw32;
          fonts = (linux pkgs).textFonts;
          sdl3 = cross.callPackage ./nix/win95-sdl.nix { };

          # nixpkgs' FreeType carries the codecs for compressed font formats,
          # which this engine does not read: it draws TrueType and CFF. Leaving
          # them in means building libpng, brotli, bzip2 and harfbuzz as well.
          #
          # Before the headers were pinned to _WIN32_WINNT 0x0400 (in
          # nix/win95-toolchain.nix) this was also necessary: brotli's
          # command-line tool called fopen_s and _sopen_s, which msvcrt20 has
          # not got, so it could not link. That default is what declarations
          # like those hang off, so the override is now a size choice rather
          # than a workaround — dropping it is a fair test of whether the
          # header default is doing its job.
          #
          # Static, because the engine links -static (see
          # cmake/toolchains/mingw-w64-common.cmake) and nixpkgs builds the
          # shared library only. Without an archive to pick, the link falls back
          # to the DLL's import library and the executable needs
          # libfreetype-6.dll, zlib1.dll and libgcc_s_dw2-1.dll beside it.
          freetype = cross.freetype.overrideAttrs (old: {
            propagatedBuildInputs = [ zlib ];
            configureFlags = (old.configureFlags or [ ]) ++ [
              "--disable-shared"
              "--enable-static"
              "--without-bzip2"
              "--without-png"
              "--without-harfbuzz"
              "--without-brotli"
            ];
          });

          # Likewise: this must be the archive, not the DLL and its import
          # library.
          zlib = cross.zlib.override { shared = false; };
        in
        cross.callPackage ./nix/win95.nix {
          src = self;
          inherit freetype zlib sdl3;
          textFonts = fonts;
        };
    in
    {
      packages = forAllSystems (pkgs: {
        # `nix build` with no attribute builds the game for this system.
        default = (linux pkgs).game;
        inherit (linux pkgs) textFonts;
      }) // forLinuxSystems (pkgs: {
        # `nix build .#win95` builds the executables for Windows 95.
        win95 = (win95 pkgs).game;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cmake
            ninja
            pkg-config
            zlib
            sdl3
            freetype
            ffmpeg-headless
            python3
          ];
        };
      });
    };
}
