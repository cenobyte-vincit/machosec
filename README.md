# machosec.sh: check the security of Mach-O 64-bit executables and application bundles
- By cenobyte <vincitamorpatriae@gmail.com> 2020
- Written and tested on macOS 10.15.7

## It is able to identify
- dyld injection vulnerabilities
- LC_RPATH vulnerabilities leading to dyld injection
- symlinks pointing to attacker controlled locations
- writable by others vulnerabilities
- missing stack canaries
- disabled PIE (ASLR)
- disabled FORTIFY_SOURCE (keeping insecure functions such as strcpy, memcpy etc.)

## And it shows (targets of interest):
- setuid and setgid executables
- files and directories writable by others
- linking to non-existent dyld's (which potentially leads to dyld injection)

## Example (on the readelf binary from Brew)
```
$ sudo ./machosec.sh /usr/local/bin/greadelf
'/usr/local/bin/greadelf'
├── not code signed
└── PIE (ASLR) disabled
```
