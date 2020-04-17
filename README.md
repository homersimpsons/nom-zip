# nom-zip

A Zip Parser written using [nom](https://crates.io/crates/nom)

## Zip Specification

The Zip Specification can be found at the following URL: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

## Features

- [x] Parses an empty Zip File (only End Of Central Directory)
- [x] Parses empty folders
- [ ] Parses files with specified compressed size (it should, tests are missing)
- [ ] Parses unspecified compressed size: needs implementation of [deflate](https://tools.ietf.org/html/rfc1951)
- [ ] Parses Zip64
- [ ] Parses Encrypted Zip
