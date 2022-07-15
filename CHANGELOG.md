## 1.1.0: July 14, 2022

* Multiple updates to address some security issues
    * Implemented `zeroize` on intermediate results
    * Removed use of `Vec` to prevent intermediate results from being sprayed over the stack
* Other improvements:
    * Now `#![no_std]` compliant
    * Removed some non-idiomatic naming
    * `PsueoRandomFunction` trait now provides its own Error

## 1.0.1: July 11, 2022 (YANKED)

* Fixed wrong category

## 1.0.0: July 11, 2022 (YANKED)

* Initial Release!
