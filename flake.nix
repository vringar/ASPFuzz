{
  description = "A reproducible development environment for ASPFuzz";

  # Flake inputs
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # also valid: "nixpkgs"
    rust-overlay.url = "github:oxalica/rust-overlay"; # A helper for Rust + Nix
  };

  # Flake outputs
  outputs = {
    self,
    nixpkgs,
    rust-overlay,
  }: let
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

    # Systems supported
    allSystems = [
      "x86_64-linux" # 64-bit Intel/AMD Linux
      "aarch64-linux" # 64-bit ARM Linux
      "x86_64-darwin" # 64-bit Intel macOS
      "aarch64-darwin" # 64-bit ARM macOS
    ];

    # Helper to provide system-specific attributes
    forAllSystems = f:
      nixpkgs.lib.genAttrs allSystems (system:
        f {
          pkgs = import nixpkgs {inherit overlays system;};
        });
  in {
    formatter.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.alejandra;
    # Development environment output
    devShells = forAllSystems ({pkgs}: {
      default = pkgs.mkShell {
        hardeningDisable = ["fortify"];
        # The Nix packages provided in the environment
        packages =
          (with pkgs; [
            # DevTools
            rustToolchain
            cargo-make
            gcc-arm-embedded
            git
            llvmPackages_18.clang
            llvmPackages_18.libcxx
            pkg-config
            zsh

            # QEMU Libraries
            glib
            libgcrypt
            llvmPackages_18.libclang
            rust-bindgen-unwrapped
            libgit2
            llvmPackages_18.libllvm

            meson
            ninja
            nettle
            python311Packages.libfdt
            python311
            pixman
            qemu
            xorg.libX11
            zlib

            # getting Rustanalyzer to work

            openssl
          ])
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [libiconv]);
        LIBCLANG_PATH = "${pkgs.llvmPackages_18.libclang.lib}/lib";
        CC = "${pkgs.llvmPackages_18.clang.out}/clang";
        CXX = "${pkgs.llvmPackages_18.clang.out}/clang++";
      };
    });
  };
}
