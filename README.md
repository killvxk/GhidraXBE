# Ghidra XBE Loader

This is a Ghidra extension that adds support for opening `.xbe` files. These
files were used by the original Xbox to store executables, so this allows
reverse-engineering them in Ghidra.

This project was also created to explore Ghidra's API, so it could also be a
useful starting point if you want to build your own extension.

## Installing

Prebuilt ZIPs are provided as [GitHub releases]. Simply download the attached
`.zip` file of the newest version (eg.
`ghidra_9.0_PUBLIC_20190313_GhidraXBE.zip`), open Ghidra, go to
`File -> Install Extensions...`, click `+` and select the downloaded file.

## Contributing

There's still a few things to implement or figure out about Ghidra's API, so
feel free to send a Pull Request.

[GitHub releases]: https://github.com/jonas-schievink/GhidraXBE/releases
