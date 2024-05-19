{
  description = "A reproducible development environment for ASPFuzz";

  # Flake inputs
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # also valid: "nixpkgs"
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay"; # A helper for Rust + Nix
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  # Flake outputs
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        # Overlays enable you to customize the Nixpkgs attribute set
        overlays = [
          # Makes a `rust-bin` attribute available in Nixpkgs
          (import rust-overlay)
          # Provides a `rustToolchain` attribute for Nixpkgs that we can use to
          # create a Rust environment
          (
            self: super: {
              rustToolchain = super.rust-bin.selectLatestNightlyWith (toolchain:
                toolchain.default.override {
                  extensions = ["rust-src" "llvm-tools-preview"];
                });
            }
          )
        ];
        pkgs = import nixpkgs {inherit overlays system;};
        nativeBuildInputs = with pkgs; [
          rustToolchain
          cargo-make
          gcc-arm-embedded
          git
          llvmPackages_18.clang
          pkg-config
          rust-bindgen-unwrapped
          llvmPackages_18.libllvm
          llvmPackages_18.libclang
          libgit2

          meson
          ninja
        ];
        buildInputs = with pkgs; [
          nettle
          zlib
          glib
          libgcrypt
          llvmPackages_18.libcxx
        ];
      in
        with pkgs; {
          formatter = alejandra;
          # Development environment output
          devShells.default = mkShell {
            inherit nativeBuildInputs buildInputs;
            hardeningDisable = ["fortify"];
            # The Nix packages provided in the environment
            packages =
              (with pkgs; [
                # DevTools
                zsh

                python311Packages.libfdt
                python311
                pixman
                xorg.libX11

                # getting Rustanalyzer to work

                openssl
              ])
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [libiconv]);
            LIBCLANG_PATH = "${pkgs.llvmPackages_18.libclang.lib}/lib";
            CC = "${pkgs.llvmPackages_18.clang.out}/clang";
            CXX = "${pkgs.llvmPackages_18.clang.out}/clang++";
          };
        }
    );
}
