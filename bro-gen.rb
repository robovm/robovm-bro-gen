#!/usr/bin/env ruby

$LOAD_PATH.unshift File.dirname(__FILE__) + "/ffi-clang/lib"

require "ffi/clang"
require 'yaml'
require 'fileutils'

class String
  def camelize
    self.dup.camelize!
  end
  def camelize!
    self.replace(self.split("_").each {|s| s.capitalize! }.join(""))
  end
  def underscore
    self.dup.underscore!
  end
  def underscore!
    self.replace(self.scan(/[A-Z][a-z]*/).join("_").downcase)
  end
end

module Bro

  def self.location_to_id(location)
    "#{location.file}:#{location.offset}"
  end
  def self.location_to_s(location)
    "#{location.file}:#{location.line}:#{location.column}"
  end
  def self.read_source_range(sr)
    file = sr.start.file
    if file
      start = sr.start.offset
      n = sr.end.offset - start
      bytes = nil
      open file, 'r' do |f|
        f.seek start
        bytes = f.read n
      end
      bytes.to_s
    else
      "?"
    end
  end
  def self.read_attribute(cursor)
    Bro::read_source_range(cursor.extent)
  end

  class Entity
    attr_accessor :id, :location, :name, :framework
    def initialize(model, cursor)
      @location = cursor ? cursor.location : nil
      @id = cursor ? Bro::location_to_id(@location) : nil
      @name = cursor ? cursor.spelling : nil
      @model = model
      @framework = @location ?
          "#{@location.file}".split(File::SEPARATOR).reverse.find_all {|e| e.match(/^.*\.framework$/)}.map {|e| e.sub(/(.*)\.framework/, '\1')}.first :
          nil
    end

    def types
      []
    end

    def java_name
      name ? ((@model.conf_classes[name] || {})['name'] || name) : ''
    end

    def pointer
      Pointer.new self
    end
  end

  class Pointer < Entity
    attr_accessor :pointee
    def initialize(pointee)
      super(nil, nil)
      @pointee = pointee
    end
    def types
      @pointee.types
    end
    def java_name
      if @pointee.is_a?(Builtin) 
        if ['byte', 'byte', 'short', 'char', 'int', 'long', 'float', 'double', 'void'].include?(@pointee.name)
          "#{@pointee.name.capitalize}Ptr"
        elsif @pointee.name == 'MachineUInt'
          "MachineSizedUIntPtr"
        elsif @pointee.name == 'MachineSInt'
          "MachineSizedSIntPtr"
        elsif @pointee.name == 'MachineFloat'
          "MachineSizedFloatPtr"
        elsif @pointee.name == 'Pointer'
          "VoidPtr.Ptr"
        else
          "VoidPtr"
        end
      elsif @pointee.is_a?(Struct) || @pointee.is_a?(Typedef) && @pointee.struct
        @pointee.java_name
      else
        "#{@pointee.java_name}.Ptr"
      end
    end
  end

  class Array < Entity
    attr_accessor :base_type, :dimensions
    def initialize(base_type, dimensions)
      super(nil, nil)
      @base_type = base_type
      @dimensions = dimensions
    end
    def types
      @base_type.types
    end
    def java_name
      if @base_type.is_a?(Builtin) 
        if ['byte', 'byte', 'short', 'char', 'int', 'long', 'float', 'double', 'void'].include?(@base_type.name)
          "#{@base_type.name.capitalize}Buffer"
        elsif @base_type.name == 'MachineUInt'
          "MachineSizedUIntPtr"
        elsif @base_type.name == 'MachineSInt'
          "MachineSizedSIntPtr"
        elsif @base_type.name == 'MachineFloat'
          "MachineSizedFloatPtr"
        elsif @base_type.name == 'Pointer'
          "VoidPtr.Ptr"
        elsif @base_type.name == 'FunctionPtr'
          "FunctionPtr"
        else
          "VoidPtr"
        end
      elsif @base_type.is_a?(Struct) || @base_type.is_a?(Typedef) && @base_type.struct
        @base_type.java_name
      else
        "#{@base_type.java_name}.Ptr"
      end
    end
  end

  class Builtin < Entity
    attr_accessor :name, :type_kinds, :java_name
    def initialize(name, type_kinds, java_name = nil)
      super(nil, nil)
      @name = name
      @type_kinds = type_kinds
      @java_name = java_name || name
    end
  end

  @@builtins = [
    Builtin.new('boolean', [:type_bool]),
    Builtin.new('byte', [:type_uchar, :type_schar, :type_char_s]),
    Builtin.new('short', [:type_ushort, :type_short]),
    Builtin.new('char', [:type_wchar, :type_char16]),
    Builtin.new('int', [:type_uint, :type_int, :type_char32]),
    Builtin.new('long', [:type_ulonglong, :type_longlong]),
    Builtin.new('float', [:type_float]),
    Builtin.new('double', [:type_double]),
    Builtin.new('MachineUInt', [:type_ulong], '@MachineSizedUInt long'),
    Builtin.new('MachineSInt', [:type_long], '@MachineSizedSInt long'),
    Builtin.new('MachineFloat', [], '@MachineSizedFloat double'),
    Builtin.new('void', [:type_void]),
    Builtin.new('Pointer', [], '@Pointer long'),
    Builtin.new('__builtin_va_list', [], 'VaList'),
    Builtin.new('ObjCBlock', [:type_block_pointer]),
    Builtin.new('FunctionPtr', [], 'FunctionPtr'),
    Builtin.new('Selector', [], 'Selector'),
  ]
  @@builtins_by_name = @@builtins.inject({}) {|h, b| h[b.name] = b ; h}
  @@builtins_by_type_kind = @@builtins.inject({}) {|h, b| b.type_kinds.each {|e| h[e] = b} ; h}
  def self.builtins_by_name(name)
    @@builtins_by_name[name]
  end
  def self.builtins_by_type_kind(kind)
    @@builtins_by_type_kind[kind]
  end

  class Attribute
    attr_accessor :source
    def initialize(source)
      @source = source
    end
  end
  class IgnoredAttribute < Attribute
    def initialize(source)
      super(source)
    end
  end
  class AvailableAttribute < Attribute
    def initialize(source)
      super(source)
      s = source.sub(/^[A-Z_]+\(/, '')
      s = s.sub(/\)$/, '')
      args = s.split(/\s*,\s*/)
      @mac_version = nil
      @ios_version = nil
      @mac_dep_version = nil
      @ios_dep_version = nil
      if source.match('^CF_[A-Z_]*AVAILABLE_IOS')
        @ios_version = args[0].sub(/_/, '.')
      elsif source.match('CF_[A-Z_]*AVAILABLE_MAC')
        @mac_version = args[0].sub(/_/, '.')
      elsif source.match('CF_[A-Z_]*AVAILABLE')
        @mac_version = args[0].sub(/_/, '.')
        @ios_version = args[1].sub(/_/, '.')
      elsif source.start_with?('CF_[A-Z_]*DEPRECATED_MAC')
        @mac_version = args[0].sub(/_/, '.')
        @mac_dep_version = args[1].sub(/_/, '.')
      elsif source.start_with?('CF_[A-Z_]*DEPRECATED_IOS')
        @ios_version = args[0].sub(/_/, '.')
        @ios_dep_version = args[1].sub(/_/, '.')
      elsif source.start_with?('CF_[A-Z_]*DEPRECATED')
        @mac_version = args[0].sub(/_/, '.')
        @mac_dep_version = args[1].sub(/_/, '.')
        @ios_version = args[2].sub(/_/, '.')
        @ios_dep_version = args[3].sub(/_/, '.')
      elsif source.start_with?('__OSX_AVAILABLE_STARTING')
        @mac_version = args[0].sub(/^__MAC_/, '').sub(/_/, '.')
        @ios_version = args[1].sub(/^__IPHONE_/, '').sub(/_/, '.')
      elsif source.start_with?('__OSX_AVAILABLE_BUT_DEPRECATED')
        @mac_version = args[0].sub(/^__MAC_/, '').sub(/_/, '.')
        @mac_dep_version = args[1].sub(/^__MAC_/, '').sub(/_/, '.')
        @ios_version = args[2].sub(/^__IPHONE_/, '').sub(/_/, '.')
        @ios_dep_version = args[3].sub(/^__IPHONE_/, '').sub(/_/, '.')
      end
      @mac_version = @mac_version == 'NA' ? nil : @mac_version
      @mac_dep_version = @mac_version == 'NA' ? nil : @mac_dep_version
      @ios_version = @ios_version == 'NA' ? nil : @ios_version
      @ios_dep_version = @ios_version == 'NA' ? nil : @ios_dep_version
    end
  end
  class UnsupportedAttribute < Attribute
    def initialize(source)
      super(source)
    end
  end

  def self.parse_attribute(cursor)
    source = Bro::read_attribute(cursor)
    if source.start_with?('__DARWIN_ALIAS_C') || source.start_with?('__DARWIN_ALIAS') || 
       source == 'CF_IMPLICIT_BRIDGING_ENABLED' || source.start_with?('DISPATCH_') || source.start_with?('CF_RETURNS_RETAINED') ||
       source == 'CF_INLINE' || source.start_with?('CF_FORMAT_FUNCTION') || source.start_with?('CF_FORMAT_ARGUMENT') || source == '__header_always_inline'
      return IgnoredAttribute.new source
    elsif source.match('CF_[A-Z_]*AVAILABLE') || source.match('CF_[A-Z_]*DEPRECATED') ||
          source.start_with?('__OSX_AVAILABLE_STARTING') || source.start_with?('__OSX_AVAILABLE_BUT_DEPRECATED')
      return AvailableAttribute.new source
    else
      return UnsupportedAttribute.new source
    end
  end

  class CallbackParameter
    attr_accessor :name, :type
    def initialize(cursor)
      @name = cursor.spelling
      @type = cursor.type
    end
  end

  class Typedef < Entity
    attr_accessor :typedef_type, :parameters, :struct, :enum
    def initialize(model, cursor)
      super(model, cursor)
      @typedef_type = cursor.typedef_type
      @parameters = []
      @struct = nil
      @enum = nil
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_parm_decl
          @parameters.push CallbackParameter.new cursor
        when :cursor_struct, :cursor_union
          @struct = Struct.new model, cursor, nil, cursor.kind == :cursor_union
        when :cursor_type_ref
          # Ignored
        when :cursor_enum_decl
          @enum = Enum.new model, cursor
        end
        next :continue
      end
    end

    def is_callback?
      !@parameters.empty?
    end

    def is_struct?
      @struct != nil
    end

    def is_enum?
      @enum != nil
    end
  end

  class StructMember
    attr_accessor :name, :type
    def initialize(cursor)
      @name = cursor.spelling
      @type = cursor.type
    end
  end

  class Struct < Entity
    attr_accessor :members, :children, :parent, :union
    def initialize(model, cursor, parent = nil, union = false)
      super(model, cursor)
      @members = []
      @children = []
      @parent = parent
      @union = union
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_field_decl
          @members.push StructMember.new cursor
        when :cursor_struct, :cursor_union
          s = Struct.new model, cursor, self, cursor.kind == :cursor_union
          model.structs.push s
          @children.push s
        when :cursor_unexposed_attr
          $stderr.puts "WARN: #{@union ? 'union' : 'struct'} #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute #{Bro::read_attribute(cursor)}"
        else
          raise "Unknown cursor kind #{cursor.kind} in struct at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
    end

    def types
      @members.map {|m| m.type}
    end

    def is_opaque?
      @members.empty?
    end

    def to_java(template, name = nil, superclass = nil)
      name = name ? name : self.name
      template = template.gsub(/\/\*<name>\*\/.*\/\*<\/name>\*\//, "/*<name>*/ #{name} /*</name>*/")
      if is_opaque?
        template = template.gsub(/\/\*<extends>\*\/.*\/\*<\/extends>\*\//, "/*<extends>*/ #{superclass} /*</extends>*/")
      else
      end
      template
    end
  end

  class FunctionParameter
    attr_accessor :name, :type
    def initialize(cursor, def_name)
      @name = cursor.spelling.size > 0 ? cursor.spelling : def_name
      @type = cursor.type
    end
  end

  class Function < Entity
    attr_accessor :return_type, :parameters, :type
    def initialize(model, cursor)
      super(model, cursor)
      @type = cursor.type
      @return_type = cursor.type.result_type
      @parameters = []
      @attributes = []
      param_count = 0
      @inline = false
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_type_ref, :cursor_obj_c_class_ref
          # Ignored
        when :cursor_parm_decl
          @parameters.push FunctionParameter.new cursor, "p#{param_count}"
          param_count = param_count + 1
        when :cursor_compound_stmt
          @inline = true
        when :cursor_asm_label_attr, :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute)
            $stderr.puts "WARN: Function #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in function #{@name} at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
    end

    def types
      @parameters.inject([@return_type]) {|a, p| a.push(p.type) ; a}
    end

    def is_variadic?
      @type.variadic?
    end

    def is_inline?
      @inline
    end
  end

  class GlobalValue < Entity
    attr_accessor :type
    def initialize(model, cursor)
      super(model, cursor)
      @type = cursor.type
    end

    def is_const?
      @type.spelling.match(/\bconst\b/) != nil
    end
  end

  class ConstantValue < Entity
    attr_accessor :value, :type
    def initialize(model, cursor, value, type = nil)
      super(model, cursor)
      @name = cursor.spelling
      @value = value
      @type = type
      if !@type
        if value.end_with?('L')
          @type = 'long'
        elsif value.end_with?('F') || value.end_with?('f')
          @type = 'float'
        elsif value.match(/^[-~]?((0x[0-9a-f]+)|([0-9]+))$/i)
          @type = 'int'
        else
          @type = 'double'
        end
      end
    end
  end

  class EnumValue
    attr_accessor :name, :value, :type, :enum
    def initialize(cursor, enum)
      @name = cursor.spelling
      @value = cursor.enum_value
      @type = cursor.type
      @enum = enum
    end
    def java_name
      if @name.start_with?(@enum.prefix)
        @name[@enum.prefix.size..-1]
      else
        @name
      end
    end
  end

  class Enum < Entity
    attr_accessor :values, :type
    def initialize(model, cursor)
      super(model, cursor)
      @values = []
      @type = cursor.type
      @enum_type = cursor.enum_type
      @attributes = []
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_enum_constant_decl
          values.push EnumValue.new cursor, self
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute)
            $stderr.puts "WARN: enum #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute #{Bro::read_attribute(cursor)}"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in enum at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
    end
    def enum_type
      # If this is a named enum (objc_fixed_enum) we take the enum int type from the first value
      @enum_type.kind == :type_enum ? @values.first.type.canonical : @enum_type
    end
    def enum_conf
      (@model.conf_enums.find { |k, v| k == name || v['first'] == values.first.name } || [{}, {}])[1]
    end
    def prefix
      if @prefix
        @prefix
      else
        name = self.name
        @prefix = enum_conf['prefix']
        if !@prefix && @values.size > 1
          # Determine common prefix
          @prefix = @values[0].name.dup
          @values[1..-1].each do |p|
            if p.enum == self
              e = p.name
              @prefix.slice!(e.size..-1) if e.size < @prefix.size   # optimisation
              @prefix.chop! while e.index(@prefix) != 0
            end
          end
        end

        if !@prefix
          $stderr.puts "WARN: Failed to determine prefix for enum #{name} with first #{@values[0].name} at #{Bro::location_to_s(@location)}"
          @prefix = ""
        end
        @prefix
      end
    end
    alias :super_name :name
    def name
      n = ((@model.conf_enums.find { |k, v| v['first'] == values.first.name }) || [nil]).first
      if !n
        if @model.cfenums.include?(@id) || @model.cfoptions.include?(@id)
          # This is a CF_ENUM or CF_OPTIONS. Find the typedef with the same location and use its name.
          td = @model.typedefs.find { |e| e.id == @id }
          n = td ? td.name : nil
        end
      end
      n || super_name
    end
    def is_options?
      @model.cfoptions.include?(@id)
    end
    def merge_with
      enum_conf['merge_with']
    end
  end

  class Model
    attr_accessor :conf, :typedefs, :functions, :global_values, :constant_values, :structs, :enums, :cfenums, :cfoptions, :conf_classes, :conf_enums, :referenced_types
    def initialize(conf)
      @conf = conf
      @conf_typedefs = @conf['typedefs'] || {}
      @conf_enums = @conf['enums'] || {}
      @conf_classes = @conf['classes'] || {}
      @typedefs = []
      @functions = []
      @global_values = []
      @constant_values = []
      @structs = []
      @enums = []
      @cfenums = [] # CF_ENUM(..., name) locations
      @cfoptions = [] # CF_OPTIONS(..., name) locations
      @type_cache = {}
      @referenced_types = []
    end
    def inspect
      object_id
    end
    def resolve_type_by_name(name)
      name = name.sub(/^(@ByVal|@Array.*)\s+/, '')
      e = Bro::builtins_by_name(name)
      e = e || @enums.find {|e| e.name == name}
      e = e || @structs.find {|e| e.name == name}
      e = e || @typedefs.find {|e| e.name == name}
      e
    end
    def resolve_type(type)
      t = @type_cache[type.spelling]
      if !t
        t = resolve_type0(type)
        raise "Failed to resolve type '#{type.spelling}' with kind #{type.kind} defined at #{Bro::location_to_s(type.declaration.location)}" unless t
        if t.is_a?(Typedef) && t.is_callback?
          # Callback. Map to VoidPtr for now.
          t = Bro::builtins_by_name("FunctionPtr")
        end
        @type_cache[type.spelling] = t
      end
      t
    end
    def resolve_type0(type)
      if !type then return Bro::builtins_by_type_kind(:type_void) end
      name = type.spelling
      name = name.gsub(/\s*\bconst\b\s*/, '')
      name = name.sub(/^(struct|enum)\s*/, '')
      if @conf_typedefs[name]
        resolve_type_by_name @conf_typedefs[name]
      elsif type.kind == :type_pointer
        e = resolve_type(type.pointee)
        if e.is_a?(Enum) || e.is_a?(Typedef) && e.is_enum?
          # Pointer to enum. Use an appropriate integer pointer (e.g. IntPtr)
          enum = e.is_a?(Enum) ? e : e.enum
          if type.pointee.canonical.kind == :type_enum
            # Pointer to objc_fixed_enum
            resolve_type(enum.enum_type).pointer
          else
            resolve_type(type.pointee.canonical).pointer
          end
        else
          e.pointer
        end
      elsif type.kind == :type_record
        @structs.find {|e| e.name == name}
      elsif type.kind == :type_enum
        @enums.find {|e| e.name == name}
      elsif type.kind == :type_unexposed
        e = @structs.find {|e| e.name == name}
        if !e
          if name.end_with?('[]')
            # type is an unbounded array (void *[]). libclang does not expose info on such types.
            # Replace all [] with *
            name = name.gsub(/\[\]/, '*')
            e = resolve_type_by_name(name.sub(/^([^\s*]+).*/, '\1'))
            if e
              # Wrap in Pointer as many times as there are *s in name
              e = (1..name.scan(/\*/).count).inject(e) {|t, i| t.pointer}
            end
          elsif name.match(/\(/)
            # Callback. libclang does not expose info for callbacks.
            e = Bro::builtins_by_name('FunctionPtr')
          end
        end
        e
      elsif type.kind == :type_typedef
        td = @typedefs.find {|e| e.name == name}
        if !td
          # Check builtins for builtin typedefs like va_list
          Bro::builtins_by_name(name)
        else
          if td.is_callback? || td.is_struct? || td.is_enum? || @conf_classes[td.name]
            td
          else
            e = @enums.find {|e| e.name == name}
            e = e || resolve_type(td.typedef_type)
            if e.is_a?(Pointer) && e.pointee.is_a?(Struct) && e.pointee.is_opaque?
              td
            else
              e
            end
          end
        end
      elsif type.kind == :type_constant_array
        dimensions = []
        base_type = type
        while base_type.kind == :type_constant_array
          dimensions.push base_type.array_size
          base_type = base_type.element_type
        end
        Array.new(resolve_type(base_type), dimensions)
      else
        # Could still be an enum
        e = @enums.find {|e| e.name == name}
        # If not check builtins
        e = e || Bro::builtins_by_type_kind(type.kind)
        # And finally typedefs
        e = e || @typedefs.find {|e| e.name == name}
        e
      end
    end

    def to_java_type(type)
      if type.is_a?(Struct) || type.is_a?(Typedef) && (type.struct || type.typedef_type.kind == :type_record)
        "@ByVal #{type.java_name}"
      elsif type.is_a?(Array)
        "@Array(#{type.dimensions.join(', ')}) #{type.java_name}"
      else
         type.java_name
       end
    end

    def is_included?(entity)
      framework = conf['framework']
      path_match = conf['path_match']
#      puts "entity.location.file = #{entity.location.file} #{path_match} #{entity.location.file.match(path_match)}"
      if path_match && entity.location.file.match(path_match)
        true
      else
        if framework
          entity.framework == framework
        else
          false
        end
      end
    end

    def process(cursor)
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_typedef_decl
          @typedefs.push Typedef.new self, cursor
          next :continue
        when :cursor_struct, :cursor_union
          if cursor.spelling
            # Ignore anonymous top-level records. They have to be accessed through a typedef
            @structs.push Struct.new self, cursor, nil, cursor.kind == :cursor_union
          end
          next :continue
        when :cursor_enum_decl
          e = Enum.new self, cursor
          if !e.values.empty?
            @enums.push(e)
          end
          next :continue
        when :cursor_macro_definition
          name = "#{cursor.spelling}"
          src = Bro::read_source_range(cursor.extent)
          if src != '?'
            src = src[name.length..-1]
            src.strip!
            while src.start_with?('(') && src.end_with?(')')
              src = src[1..-2]
            end
            # Only include macros that look like integer or floating point values for now
            if src =~ /^(([-+.0-9Ee]+[fF]?)|(~?0x[0-9a-fA-F]+[UL]*)|(~?[0-9]+[UL]*))$/i
              value = $1
              value = value.sub(/^((0x)?.*)U$/i, '\1')
              value = value.sub(/^((0x)?.*)ULL$/i, '\1L')
              value = value.sub(/^((0x)?.*)LL$/i, '\1L')
              @constant_values.push ConstantValue.new self, cursor, value
            else
              v = @constant_values.find {|e| e.name == src}
              if v
                @constant_values.push ConstantValue.new self, cursor, v.value, v.type
              end
            end
          end
          next :continue
        when :cursor_macro_expansion
          if cursor.spelling.to_s == "CF_ENUM"
            @cfenums.push Bro::location_to_id(cursor.location)
          elsif cursor.spelling.to_s == "CF_OPTIONS"
            @cfoptions.push Bro::location_to_id(cursor.location)
          end
          next :continue
        when :cursor_function
          @functions.push Function.new self, cursor
          next :continue
        when :cursor_variable
          @global_values.push GlobalValue.new self, cursor
          next :continue
        else
          next :recurse
        end
      end

      # Sort structs so that opaque structs come last. If a struct has a definition it should be used and not the forward declaration.
      @structs = @structs.sort {|a, b| (a.is_opaque? ? 1 : 0) <=> (b.is_opaque? ? 1 : 0) }

      # Merge enums
      enums = @enums.map do |e|
        if e.merge_with
          other = @enums.find {|f| e.merge_with == f.name}
          if !other
            raise "Cannot find other enum '#{e.merge_with}' to merge enum #{e.name} at #{Bro::location_to_s(e.location)} with"
          end
          other.values.push(e.values).flatten!
          nil
        else 
          e
        end
      end
      enums = enums.find_all {|e| e}
      @enums = enums

      # Filter out functions not defined in the framework or library we're generating code for
      @functions = @functions.find_all {|f| is_included?(f)}

      # Filter out varidadic and inline functions
      @functions = @functions.find_all do |f|
        if f.is_variadic? || f.is_inline? || !f.parameters.empty? && f.parameters[-1].type.spelling == 'va_list'
          definition = f.type.spelling.sub(/\(/, "#{f.name}(")
          $stderr.puts "WARN: Ignoring #{f.is_variadic? ? 'variadic' : 'inline'} function '#{definition}' at #{Bro::location_to_s(f.location)}"
          false
        else
          true
        end
      end

      # Filter out global values not defined in the framework or library we're generating code for
      @global_values = @global_values.find_all {|v| is_included?(v)}

      # Filter out constants not defined in the framework or library we're generating code for
      @constant_values = @constant_values.find_all {|v| is_included?(v)}

      # Create a hash of referenced types. The key is the name of the type where it is used. The values
      # are arrays [type, canonical, referers] where typedef is the used type (possibly a typedef),
      # canonical is the canonical type (typedefs have been resolved) and referers is an array of
      # users of the type.
      def merge_func(key, oldval, newval)
        oldval[2].push(newval[2][0])
        oldval
      end
      def unwrap_pointer(t)
        while t.is_a?(Bro::Pointer)
          t = t.pointee
        end
        t
      end
      def unwrap_typedef(u)
        while u.is_a?(Typedef) && !u.is_callback? && !@conf_classes[u.name]
          u = u.struct || u.enum || unwrap_pointer(resolve_type(u.typedef_type
            ))
        end
        u
      end
      def find_referenced_types(t, referer, visited)
        t = unwrap_pointer(t)
        t = t.is_a?(Array) ? t.base_type : t
        if t.is_a?(Builtin)
          {}
        else
          if !visited.include?(t)
            u = unwrap_typedef(t)
            visited.push(t)
            u.types.inject(t == referer ? {} : {t.name => [t, u, referer ? [referer] : []]}) {|h, t2| h.merge!(find_referenced_types(resolve_type(t2), u, visited), &method(:merge_func)) }
          else
            {}
          end
        end
      end
      referenced_types = @functions.inject({}) {|h, f| h.merge!(find_referenced_types(f, f, []), &method(:merge_func)) }
      referenced_types.merge!(@global_values.inject({}) {|h, v| h.merge!(find_referenced_types(v, v, []), &method(:merge_func)) }, &method(:merge_func))

      # Add types referenced by the config
      conf_types = (@conf['functions'] || {}).values.map {|h| (h['parameters'] || {}).values.map {|p| p['type']} + [h['return_type']] }.flatten.find_all {|e| e}.uniq
      conf_types = conf_types + (@conf['force_types'] || [])
      conf_types = conf_types + ((@conf['classes'] || {}).map {|(k, v)| k})
      conf_types = conf_types + ((@conf['enums'] || {}).map {|(k, v)| k})
      conf_types = conf_types.map {|e| resolve_type_by_name(e)}.find_all {|e| e}
      #puts conf_types.map {|e| "#{e.class.name}(#{e.name})"}.inspect
      referenced_types.merge!(conf_types.inject({}) {|h, t| h[t.name] = [t, t, []]; h}, &method(:merge_func))

      # Remove types not defined in the framework or library
      lib = conf['framework'] || conf['library']
      referenced_types = referenced_types.inject({}) do |h, (k, v)|
        if (@conf['force_types'] || []).include?(k) || is_included?(v[0])
          h[k] = v
        else
          $stderr.puts "WARN: The referenced type '#{k}' defined at #{Bro::location_to_s(v[0].location)} is not in #{lib}. It will not be generated. Referenced by #{v[2].map {|e| e ? e.name : '?'}}"
        end
        h
      end

      #puts referenced_types.map { |k, v| "#{k} => #{v[0].name} #{v[1].name}"}

      # Detect canonical types referenced multiple times through different typedefs and error out if one is found
      referenced_types_renamed = referenced_types.inject({}) {|h, (k, v)| h[(@conf_classes[k] || {})['name'] || k] = v; h}
      # We allow multiple typedefs referencing the same opaque struct so filter out opaque structs
      canonical_types = referenced_types_renamed.values.map {|e| e[1]}.find_all {|e| !e.is_a?(Builtin) && (!e.is_a?(Struct) || !e.is_opaque?)}
      dup_types = canonical_types.inject({}) {|h, t| h[t] = (h[t] || 0) + 1 ; h}.find_all {|k, v| v > 1}.map {|k, v| k}
      dup_types.each do |t|
        raise "The type '#{t.name}' defined at #{t.location ? Bro::location_to_s(t.location) : ''} is referenced multiple times using different names"
      end
      @referenced_types = referenced_types

      # Find unreferenced enums and warn about those with names which are in the framework or library
      unreferenced_enums = @enums - @referenced_types.map {|k, v| v[1].is_a?(Enum) ? v[1] : nil}.find_all {|e| e}
      unreferenced_enums = unreferenced_enums.find_all {|e| is_included?(e)}
      unreferenced_enums.each do |enum|
        if enum.java_name && enum.java_name.size > 0
          $stderr.puts "WARN: An unreferenced enum '#{enum.java_name}' defined at #{Bro::location_to_s(enum.location)} is in #{lib}"
        end
      end

      # Create ConstantValues for remaining unnamed enums
      unreferenced_enums.each do |enum|
        if !enum.java_name || enum.java_name.size == 0
          type = [:type_longlong, :type_ulonglong].include?(enum.enum_type.kind) ? 'long' : 'int'
          enum.type.declaration.visit_children do |cursor, parent|
            case cursor.kind
            when :cursor_enum_constant_decl
              @constant_values.push ConstantValue.new self, cursor, cursor.enum_value, type
            end
            next :continue
          end
        end
      end
      #puts unreferenced_enums.map {|e| "#{e.java_name || 'unnamed'} { #{e.values.map {|v| v.name}.join(', ')} }"}
    end

    # Returns all referenced structs in an array of (type, canonical) pairs. type
    # is the referenced typedef (or the struct if referenced directly) while 
    # canonical is the Struct instance. Does not return opaque structs.
    def referenced_structs
      @referenced_types.map {|k, v| v[1].is_a?(Struct) && !v[1].is_opaque? ? v : nil}.find_all {|e| e}
    end

    # Returns all referenced opaque structs in an array of (type, canonical) pairs. type
    # is the referenced typedef (or the struct if referenced directly) while 
    # canonical is the Struct instance.
    def referenced_opaques
      @referenced_types.map {|k, v| v[1].is_a?(Typedef) || v[1].is_a?(Struct) && v[1].is_opaque? ? v : nil}.find_all {|e| e}
    end

    # Returns all referenced enums in an array of (type, canonical) pairs. type
    # is the referenced typedef (or the enum if referenced directly) while 
    # canonical is the Enum instance.
    def referenced_enums
      @referenced_types.map {|k, v| v[1].is_a?(Enum) ? v : nil}.find_all {|e| e}
    end
  end
end

sysroot = '/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.0.sdk'

def dump_ast(cursor, indent)
  cursor.visit_children do |cursor, parent|
    if cursor.kind != :cursor_macro_definition && cursor.kind != :cursor_macro_expansion && cursor.kind != :cursor_inclusion_directive
      puts "#{indent}#{cursor.kind} '#{cursor.spelling}' #{cursor.type.kind} '#{cursor.type.spelling}' #{cursor.typedef_type ? cursor.typedef_type.kind : ''} #{Bro::location_to_s(cursor.location)}"
    end
    dump_ast cursor, "#{indent}  "
    next :continue
  end
end

def target_file(dir, package, name)
  File.join(dir, package.gsub('.', File::SEPARATOR), "#{name}.java")
end

def load_template(dir, package, name, def_template)
  f = target_file(dir, package, name)
  FileUtils.mkdir_p(File.dirname(f))
  File.size?(f) ? IO.read(f) : def_template
end

def merge_template(dir, package, name, def_template, data)
  template = load_template(dir, package, name, def_template)
  if package.size > 0
    template = template.sub(/^package .*;/, "package #{package};")
  end
  data.each do |key, value|
    template = template.gsub(/\/\*<#{key}>\*\/.*?\/\*<\/#{key}>\*\//m, "/*<#{key}>*/#{value}/*</#{key}>*/")
  end
  open(target_file(dir, package, name), 'wb') do |f|
    f << template
  end
end

def find_conf_matching(name, conf)
  match = conf.find {|pattern, value| name.match(pattern)}
  if !match
    {}
  elsif !$~.captures.empty?
    def get_binding(g)
      binding
    end
    b = get_binding($~.captures)
    # Perform substitution on children
    captures = $~.captures
    h = {}
    match[1].keys.each do |key|
      v = match[1][key]
      if v.is_a?(String) && v.match(/#\{/)
        v = eval("\"#{v}\"", b)
      end
      h[key] = v
    end
    h
  else
    match[1]
  end
end
def get_conf_for_key(name, conf)
  conf[name] || find_conf_matching(name, conf) || {}
end

script_dir = File.expand_path(File.dirname(__FILE__))
target_dir = ARGV[0]
def_class_template = IO.read("#{script_dir}/class_template.java")
def_enum_template = IO.read("#{script_dir}/enum_template.java")
def_bits_template = IO.read("#{script_dir}/bits_template.java")
def_protocol_template = IO.read("#{script_dir}/protocol_template.java")
global = YAML.load_file("#{script_dir}/global.yaml")

ARGV[1..-1].each do |yaml_file|
  conf = YAML.load_file(yaml_file)

  header = conf['header'] || abort("Required 'header' value missing in #{yaml_file}")

  conf = global.merge conf
  conf['typedefs'] = (global['typedefs'] || {}).merge(conf['typedefs'] || {})

  (conf['include'] || []).each do |f|
    c = YAML.load_file(f)
    conf['classes'] = (c['classes'] || {}).merge(conf['classes'] || {})
    conf['enums'] = (c['enums'] || {}).merge(conf['enums'] || {})
    conf['typedefs'] = (c['typedefs'] || {}).merge(conf['typedefs'] || {})
  end

  index = FFI::Clang::Index.new
  #translation_unit = index.parse_translation_unit(header, ['-arch', 'armv7', '-mthumb', '-miphoneos-version-min', '7.0', '-fblocks', '-x', 'objective-c', '-isysroot', sysroot], [], {:detailed_preprocessing_record=>true})
  translation_unit = index.parse_translation_unit("#{sysroot}#{header}", ['-arch', 'armv7', '-mthumb', '-miphoneos-version-min', '7.0', '-fblocks', '-x', 'objective-c', '-isysroot', sysroot], [], {:detailed_preprocessing_record=>true})
  #translation_unit = index.parse_translation_unit("#{sysroot}#{header}", ['-arch', 'armv7', '-mthumb', '-miphoneos-version-min', '7.0', '-isysroot', sysroot], [], {:detailed_preprocessing_record=>true})
  #dump_ast translation_unit.cursor, ""
  #exit

  model = Bro::Model.new conf
  model.process(translation_unit.cursor)

  package = conf['package'] || ''
  library = conf['library'] || ''
  default_class = conf['default_class'] || conf['framework'] || 'Functions'

  imports = conf['imports'] || []
  imports << "java.nio.*"
  imports << "java.util.*"
  imports << "org.robovm.objc.*"
  imports << "org.robovm.objc.annotation.*"
  imports << "org.robovm.objc.block.*"
  imports << "org.robovm.rt.bro.*"
  imports << "org.robovm.rt.bro.annotation.*"
  imports << "org.robovm.rt.bro.ptr.*"
  imports.uniq!

  imports_s = "\n" + imports.map {|im| "import #{im};"}.join("\n") + "\n"

  conf_enums = conf['enums'] || {}
  model.referenced_enums.each do |pair|
    td = pair[0]
    enum = pair[1]
    data = {}
    econf = get_conf_for_key(td.java_name, conf_enums) 
    java_name = td.java_name
    bits = enum.is_options? || econf['bits']
    if bits
      values = enum.values.map { |e| "public static final #{java_name} #{e.java_name} = new #{td.java_name}(#{e.value})" }.join(";\n    ") + ";"
    else
      values = enum.values.map { |e| "#{e.java_name}(#{e.value})" }.join(",\n    ") + ";"
    end
    data['values'] = "\n    #{values}\n    "
    data['name'] = java_name
    if econf['marshaler']
      data['annotations'] = "@Marshaler(#{econf['marshaler']}.class)"
    else
      enum_type = model.resolve_type(enum.enum_type)
      if enum_type.name =~ /^Machine(.)Int$/
        if !bits
          data['annotations'] = "@Marshaler(ValuedEnum.AsMachineSized#{$1}IntMarshaler.class)"
        else
          data['annotations'] = "@Marshaler(Bits.AsMachineSizedIntMarshaler.class)"
        end
      else
        typedefedas = model.typedefs.find {|e| e.name == java_name}
        if typedefedas
          if typedefedas.typedef_type.spelling == 'CFIndex'
            data['annotations'] = "@Marshaler(ValuedEnum.AsMachineSizedSIntMarshaler.class)"
          elsif typedefedas.typedef_type.spelling == 'CFOptionFlags'
            data['annotations'] = "@Marshaler(Bits.AsMachineSizedIntMarshaler.class)"
          end
        end
      end
    end
    data['imports'] = imports_s
    merge_template(target_dir, package, java_name, bits ? def_bits_template : def_enum_template, data)
  end

  template_datas = {}

  conf_structs = conf['structs'] || {}
  model.referenced_structs.each do |pair|
    td = pair[0]
    struct = pair[1]

    data = template_datas[td.java_name] || {}
    sconf = get_conf_for_key(td.java_name, conf_structs) 

    inc = struct.union ? 0 : 1
    index = 0
    members = []
    struct.members.each do |e|
      type = (sconf[e.name] || {})['type'] || model.to_java_type(model.resolve_type(e.type))
      members.push(["@StructMember(#{index}) public native #{type} #{e.name}();", "@StructMember(#{index}) public native #{td.java_name} #{e.name}(#{type} #{e.name});"].join("\n    "))
      index = index + inc
    end
    members = members.join("\n    ")
    data['methods'] = "\n    #{members}\n    "

    constructor_params = []
    constructor_body = []
    struct.members.map do |e|
      type = (sconf[e.name] || {})['type']
      type = type ? type.sub(/^(@ByVal|@Array.*)\s+/, '') : model.resolve_type(e.type).java_name
      constructor_params.push "#{type} #{e.name}"
      constructor_body.push "this.#{e.name}(#{e.name});"
    end.join("\n    ")
    constructor = "public #{td.java_name}(" + constructor_params.join(', ') + ") {\n        "
    constructor = constructor + constructor_body.join("\n        ")
    constructor = "#{constructor}\n    }"
    data['constructors'] = "\n    #{constructor}\n    "

    data['name'] = td.java_name
    data['visibility'] = sconf['visibility'] || 'public'
    data['extends'] = "Struct<#{td.java_name}>"
    data['imports'] = imports_s
    data['ptr'] = "public static class Ptr extends org.robovm.rt.bro.ptr.Ptr<#{td.java_name}, Ptr> {}"

    template_datas[td.java_name] = data
  end

  model.referenced_opaques.each do |pair|
    td = pair[0]
    c = model.conf_classes[td.name] || {}
    data = template_datas[td.java_name] || {}
    data['name'] = td.java_name
    data['visibility'] = c['visibility'] || 'public'
    data['extends'] = c['extends'] || data['extends'] || 'NativeObject'
    data['imports'] = imports_s
    data['ptr'] = "public static class Ptr extends org.robovm.rt.bro.ptr.Ptr<#{td.java_name}, Ptr> {}"
    template_datas[td.java_name] = data
  end

  # Assign global values to classes
  conf_values = conf['values'] || {}
  values = {}
  model.global_values.each do |v|
    vconf = get_conf_for_key(v.name, conf_values) 
    if !vconf['exclude']
      owner = vconf['class'] || default_class
      values[owner] = (values[owner] || []).push([v, vconf])
    end
  end

  # Generate template data for global values
  values.each do |owner, vals|
    data = template_datas[owner] || {}
    data['name'] = owner
    methods_s = vals.map do |(v, vconf)|
      name = vconf['name'] || v.name
      #name = name[0, 1].downcase + name[1..-1]
      java_type = vconf['type'] || model.to_java_type(model.resolve_type(v.type))
      visibility = vconf['visibility'] || 'public'
      lines = ["@GlobalValue(symbol=\"#{v.name}\")", "#{visibility} static native #{java_type} #{name}();"]
      if !v.is_const? && !vconf['readonly']
        lines = lines + ["@GlobalValue(symbol=\"#{v.name}\")", "public static native void #{name}(#{java_type} v);"]
      end
      lines
    end.flatten.join("\n    ")
    data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
    data['imports'] = imports_s
    data['annotations'] = "@Library(\"#{library}\")"
    data['bind'] = "static { Bro.bind(#{owner}.class); }"
    template_datas[owner] = data
  end

  # Assign functions to classes
  conf_functions = conf['functions'] || {}
  functions = {}
  model.functions.each do |f|
    fconf = get_conf_for_key(f.name, conf_functions) 
    if !fconf['exclude']
      owner = fconf['class'] || default_class
      functions[owner] = (functions[owner] || []).push([f, fconf])
    end
  end

  # Generate template data for functions
  functions.each do |owner, funcs|
    data = template_datas[owner] || {}
    data['name'] = owner
    methods_s = funcs.map do |(f, fconf)|
      name = fconf['name'] || f.name
      name = name[0, 1].downcase + name[1..-1]
      visibility = fconf['visibility'] || 'public'
      parameters = f.parameters
      static = "static "
      if parameters.size >= 1 && model.resolve_type(parameters[0].type).java_name == owner
        # Instance method
        parameters = parameters[1..-1]
        static = ""
      end
      java_ret = fconf['return_type'] || model.to_java_type(model.resolve_type(f.return_type))
      #if f.ret
      paramconf = fconf['parameters'] || {}
      java_parameters = parameters.map do |e|
        pconf = paramconf[e.name] || {}
        "#{pconf['type'] || model.to_java_type(model.resolve_type(e.type))} #{pconf['name'] || e.name}"
      end
      ["@Bridge(symbol=\"#{f.name}\")", "#{visibility} #{static}native #{java_ret} #{name}(#{java_parameters.join(', ')});"]
    end.flatten.join("\n    ")
    data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
    data['imports'] = imports_s
    data['annotations'] = "@Library(\"#{library}\")"
    data['bind'] = "static { Bro.bind(#{owner}.class); }"
    template_datas[owner] = data
  end

  # Assign constants to classes
  conf_constants = conf['constants'] || {}
  constants = {}
  model.constant_values.each do |v|
    vconf = get_conf_for_key(v.name, conf_constants) 
    if !vconf['exclude']
      owner = vconf['class'] || default_class
      constants[owner] = (constants[owner] || []).push([v, vconf])
    end
  end

  # Generate template data for constants
  constants.each do |owner, vals|
    data = template_datas[owner] || {}
    data['name'] = owner
    constants_s = vals.map do |(v, vconf)|
      name = vconf['name'] || v.name
      # TODO: Determine type more intelligently?
      java_type = vconf['type'] || v.type || 'double'
      ["public static final #{java_type} #{name} = #{v.value};"]
    end.flatten.join("\n    ")
    data['constants'] = (data['constants'] || '') + "\n    #{constants_s}\n    "
    data['imports'] = imports_s
    template_datas[owner] = data
  end

  template_datas.each do |owner, data|
    merge_template(target_dir, package, owner, def_class_template, data)
  end

  #puts model.constant_values.map { |e| "#{e.name} = #{e.value} (#{e.framework})" }

end
