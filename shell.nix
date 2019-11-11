{ pkgs ? import <nixpkgs> { } }:

let
  compilation = with pkgs; [
    cargo
    gmp.dev
    llvmPackages.clang
    llvmPackages.libclang
    nettle
    pkgconfig
  ];
  testing = with pkgs; [ gnupg ];
  tools = with pkgs; [ cargo-watch nixfmt rustPackages.clippy rustfmt ];
in pkgs.mkShell {
  nativeBuildInputs = compilation ++ testing ++ tools;
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang}/lib";
}
