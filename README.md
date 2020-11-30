# Kiteshield

An obfuscating packer for ELF binaries on Linux. Encrypts input binaries with a
randomly generated RC4 key and injects them with loader code that decrypts,
maps and executes them in userspace at runtime.

This is intended to be a fun academic exercise in binary obfuscation rather
than something that can be used in the real world given that the source code,
and thus how it works, is public.

Currently in earlyish development, one layer of encryption is implmemented
(see code referring to the "outer layer" in packer/kiteshield.c), one more
remains (per-function encryption and dynamic in-memory decryption at runtime).
This README will be fully fleshed out when it's done.

## License

[MIT](https://github.com/GunshipPenguin/kiteshield/blob/master/LICENSE) © Rhys Rustad-Elliott

