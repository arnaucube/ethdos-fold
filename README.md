# ethdos-fold
Follows the ideas of ETHdos (https://ethdos.xyz/blog), but using folding schemes.
It uses <a target="_blank" href="https://github.com/privacy-scaling-explorations/sonobe">Sonobe</a> under the hood, compiled to WASM.

## Usage
- run native tests: `cargo test --release -- --nocapture`
- build wasm: `wasm-pack build --target web`
- serve the web: `python -m http.server 8080`
  - go to http://127.0.0.1:8080/index.html


## Acknowledgements
Thanks to Michael Chu for proposing to build this prototype. This repo uses [Sonobe](https://github.com/privacy-scaling-explorations/sonobe), which relies on [arkworks-rs](https://github.com/arkworks-rs), and for the BabyJubJub EdDSA it uses [kilic/arkeddsa](https://github.com/kilic/arkeddsa).
