Requirements

 * libclang 3.3+ (will use the one from Xcode if installed)
 * Ruby
 * Ruby FFI:
```
sudo ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future gem install ffi
```

Getting the code

```
git clone git://github.com/robovm/robovm-bro-gen.git
cd robovm-bro-gen
git submodule init
git submodule update
```

Usage

```
./bro-gen path/to/put/generated/sources config1.yaml [config2.yaml ...]
```
