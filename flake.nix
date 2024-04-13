{
  description = "A reproducible development environment for ASPFuzz";

  # Flake inputs
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # also valid: "nixpkgs"
    rust-overlay.url = "github:oxalica/rust-overlay"; # A helper for Rust + Nix
  };

  # Flake outputs
  outputs = { self, nixpkgs, rust-overlay }:
    let
      # Overlays enable you to customize the Nixpkgs attribute set
      overlays = [
        # Makes a `rust-bin` attribute available in Nixpkgs
        (import rust-overlay)
        # Provides a `rustToolchain` attribute for Nixpkgs that we can use to
        # create a Rust environment
        (self: super: {
          rustToolchain = super.rust-bin.stable.latest.default;
        })
      ];

      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      # Helper to provide system-specific attributes
      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit overlays system; };
      });
    in
    { 
      # Development environment output
      devShells = forAllSystems ({ pkgs }: {
        default = pkgs.mkShell {
          hardeningDisable = [ "fortify" ];
          # The Nix packages provided in the environment
          packages = (with pkgs; [
            # DevTools
            rustToolchain
            cargo-make
            gcc-arm-embedded
            git
            clang
            clang_17
            libcxx
            pkg-config
            zsh

            # QEMU Libraries
            glib
            libgcrypt
            libclang
            rust-bindgen-unwrapped
            libgit2
            libllvm

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
          ]) ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [ libiconv ]);
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          CC = "${pkgs.clang.out}/clang";
          CXX = "${pkgs.clang.out}/clang++";
        };
      });
    };
}
