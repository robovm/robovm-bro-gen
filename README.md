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
 * `categories`: A hash of Obj-C categories that should be generated. See below.
 * `protocols`: A hash of Obj-C protocols that should be generated. See below.
 * `functions`: A hash of C functions that should be generated. See below.
 * `values`: A hash of C global values that should be generated. See below.
 * `constants`: A hash of C constants that should be generated. See below.

###enums

The keys in this hash specify enum names. Only enums that have a matching key in this hash will be generated. The values are also hashes, usually empty (`{}`) but the following keys are supported:

 * `first`: The name of the first member in the enum. Some enums don't specify a name in the header file. This will be used to connect an anonymous enum with a name (the key of the `enums` hash).
 * `prefix`: The prefix of the member names which should be stripped off when generating the Java member name. The script will look for the longest common prefix of the names and use that as prefix by default.
 * `suffix`: A suffix which should be stripped off the end of member names if they end with this suffix.
 * `type`: The C type of the enum. This is used to determine the marshaler to use in the Java code. This can usally be determined automatically be the script.
 * `merge_with`: Another enum which this enum should be merged with.
 * `bits`: Boolean specifying whether this should be bound as a Java enum or as a Java class inheriting from Bits. Should be `true` if the C enum is a bitmask kind of enum. For Apple's header files this can usually be determined automatically by the script.
 * `exclude`: Boolean specifying whether this enum should be excluded and not generated.
 * `ignore`: Regexp matching enum members that should be ignored.
 * `marshaler`: Specifies the `@Marshaler` to use when marhsaling this enum. E.g. `Bits.AsMachineSizedIntMarshaler`, `ValuedEnum.AsMachineSizedUIntMarshaler`. Can ususally be determined automatically by the script.
 * `<MemberName>`: Used to rename a member completely. Use the C member name as key and the Java member name as value.

###classes

The keys in this hash specify class/struct name regexp patterns. Only classes/structs that have a matching key in this hash will be generated. The values are also hashes with the following supported keys:

 * `exclude`: Boolean specifying whether this class should be excluded and not generated.
 * `visibility`: The visibility (access modifiers) of the generated class. The default is `public`.
 * `name`: The name of the generated Java class. If not specified the C/Objective-C name will be used.
 * `extends`: The name of the Java class the generated class will derive from.
 * `implements`: A list of Java interface names the generated class will implement.
 * `properties`: See below.
 * `methods`: See below.

###protocols

The keys in this hash specify Objective-C protocol name regexp patterns. Only protocols that have a matching key in this hash will be generated. A Java interface will be generated for each matching protocol along with an adapter class implementing all methods in the interface.

The values are also hashes with the following supported keys:

 * `exclude`: Boolean specifying whether this class should be excluded and not generated.
 * `visibility`: The visibility (access modifiers) of the generated class. The default is `public`.
 * `name`: The name of the generated Java class. If not specified the C/Objective-C name will be used.
 * `extends`: The name of the Java class the generated class will derive from.
 * `implements`: A list of Java interface names the generated class will implement.
 * `properties`: See below.
 * `methods`: See below.
 * `skip_adapter`: Boolean specifying whether an adapter should be generated for the Java interface. The default is `true`.

###categories

The keys in this hash specify regexps that matches Objective-C category names or Objective-C category target class names or both of them concatenated and separated by a `@`. For categories targeting classes in the current framework the default is to add the category methods to that class. For other categories the default is to create a new class with the name `<category>Extensions` that extends `NSExtensions` and that has static methods for each category method.

 * `exclude`: Boolean specifying whether this category should be excluded and not generated.
 * `protocol`: Boolean. If `true` the category will be treated as a protocol. A matching config has to exist in the `protocols` hash. Used for informal protocols.
 * `owner`: The name of the class the category methods should be added to. If not specified the methods will be added to a new class called `<category>Extensions`, e.g. `NSValueExtensions`.
 * `properties`: See below.
 * `methods`: See below.

###properties

###methods

