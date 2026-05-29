# Changelog
All notable changes to this project will be documented in this file.

## [0.2.0]
- Changed jwt library from Authlib to joserfc, since Authlib support for jwt is deprecated.
- Ensure challenges are passed to single getter by ``MultiGetter``.
- Dropped support for old python version. The library now requires python 3.10.
- Fully typed the library.

## [0.1.0]
- Add JWT support.

## [0.0.2]
- Async support for falcon v3+

## [0.0.1]
- Fist version