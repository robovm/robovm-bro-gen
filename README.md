#bro-gen

`bro-gen` is a Ruby script which can be used to generate RoboVM bindings for C/Objective-C libraries and frameworks.

##Requirements

 * libclang 3.3+ (will use the one from Xcode if installed)
 * Ruby
 * Ruby FFI

*Note about Ruby FFI*: If you get clang compiler errors when trying to install the FFI gem try the following:
```
sudo ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future gem install ffi
```

##Getting the code

```
git clone git://github.com/robovm/robovm-bro-gen.git
cd robovm-bro-gen
git submodule init
git submodule update
```

##Usage

```
./bro-gen path/to/put/generated/sources config1.yaml [config2.yaml ...]
```

##YAML config file format

The YAML config files are used to tell the script how to process the functions, classes, enums, structs, etc in a particular framework or library. The supported top level keys are:

 * `package`: The Java package name to use for all classes and interfaces.
 * `include`: A list of other YAML config files needed by this config. Will be resolved relative to the current file.
 * `library`: The library name to use in the `@Library` annotation on generated classes.
 * `framework`: The framework being generated. Only entities in header files from this framework will be included in the generated output (and header files matching `path_match`).
 * `path_match`: A regexp matching header files which contains entities that should be included in the generated output.
 * `clang_args`: List of extra arguments to pass to CLang when parsing the header files. If you generate code for an Objective-C framework you should specify `['-x', 'objective-c']`.
 * `headers`: A list of header files that should be processed relative to the sysroot.
 * `typedefs`: A hash of C/Obj-C type to Java type mappings.
 * `enums`: A hash of C enums that should be generated. See below.
 * `classes`: A hash of C structs and Obj-C classes that should be generated. See below.
 * `protocols`: A hash of Obj-C protocols that should be generated. See below.
 * `functions`: A hash of C functions that should be generated. See below.
 * `values`: A hash of C global values that should be generated. See below.
 * `constants`: A hash of C constants that should be generated. See below.

