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
      name ? ((@model.get_class_conf(name) || {})['name'] || name) : ''
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
          "VoidPtr.VoidPtrPtr"
        else
          "#{@pointee.java_name}.#{@pointee.java_name}Ptr"
        end
      elsif @pointee.is_a?(Struct) || @pointee.is_a?(Typedef) && @pointee.struct || @pointee.is_a?(ObjCClass) || @pointee.is_a?(ObjCProtocol)
        @pointee.java_name
      else
        "#{@pointee.java_name}.#{@pointee.java_name}Ptr"
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
          "VoidPtr.VoidPtrPtr"
        else
          "#{@base_type.java_name}.#{@base_type.java_name}Ptr"
        end
      elsif @base_type.is_a?(Struct) || @base_type.is_a?(Typedef) && @base_type.struct
        @base_type.java_name
      else
        "#{@base_type.java_name}.#{@base_type.java_name}Ptr"
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
    Builtin.new('Selector', [:type_obj_c_sel], 'Selector'),
    Builtin.new('ObjCObject', [], 'ObjCObject'),
    Builtin.new('ObjCClass', [], 'ObjCClass'),
    Builtin.new('ObjCProtocol', [], 'ObjCProtocol'),
    Builtin.new('BytePtr', [], 'BytePtr'),
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
      if source.match('^(CF|NS)_[A-Z_]*AVAILABLE_IOS')
        @ios_version = args[0].sub(/_/, '.')
      elsif source.match('(CF|NS)_[A-Z_]*AVAILABLE_MAC')
        @mac_version = args[0].sub(/_/, '.')
      elsif source.match('(CF|NS)_[A-Z_]*AVAILABLE')
        @mac_version = args[0].sub(/_/, '.')
        @ios_version = args[1].sub(/_/, '.')
      elsif source.start_with?('^(CF|NS)_[A-Z_]*DEPRECATED_MAC')
        @mac_version = args[0].sub(/_/, '.')
        @mac_dep_version = args[1].sub(/_/, '.')
      elsif source.start_with?('^(CF|NS)_[A-Z_]*DEPRECATED_IOS')
        @ios_version = args[0].sub(/_/, '.')
        @ios_dep_version = args[1].sub(/_/, '.')
      elsif source.start_with?('^(CF|NS)_[A-Z_]*DEPRECATED')
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
  class UnavailableAttribute < Attribute
  end
  class UnsupportedAttribute < Attribute
    def initialize(source)
      super(source)
    end
  end

  def self.parse_attribute(cursor)
    source = Bro::read_attribute(cursor)
    if source.start_with?('__DARWIN_ALIAS_C') || source.start_with?('__DARWIN_ALIAS') || 
       source == 'CF_IMPLICIT_BRIDGING_ENABLED' || source.start_with?('DISPATCH_') || source.match(/^(CF|NS)_RETURNS_RETAINED/) ||
       source.match(/^(CF|NS)_INLINE$/) || source.match(/^(CF|NS)_FORMAT_FUNCTION.*/) || source.match(/^(CF|NS)_FORMAT_ARGUMENT.*/) || 
       source == 'NS_RETURNS_INNER_POINTER' || source == 'NS_AUTOMATED_REFCOUNT_WEAK_UNAVAILABLE' ||
       source == 'NS_ROOT_CLASS' || source == '__header_always_inline'
      return IgnoredAttribute.new source
    elsif source == 'NS_UNAVAILABLE'
      return UnavailableAttribute.new source
    elsif source.match(/^(CF|NS)[A-Z_]*_AVAILABLE.*/) || source.match(/^(CF|NS)[A-Z_]*_DEPRECATED/) ||
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
      @return_type = cursor.result_type
      @parameters = []
      @attributes = []
      param_count = 0
      @inline = false
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_type_ref, :cursor_obj_c_class_ref, :cursor_obj_c_protocol_ref
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
      [@return_type] + @parameters.map {|e| e.type}
    end

    def is_variadic?
      @type.variadic?
    end

    def is_inline?
      @inline
    end
  end

  class ObjCVar < Entity
    attr_accessor :type
    def initialize(model, cursor)
      super(model, cursor)
      @type = cursor.type
    end
    def types
      [@type]
    end
  end
  class ObjCInstanceVar < ObjCVar
  end
  class ObjCClassVar < ObjCVar
  end
  class ObjCInstanceMethod < Function
    attr_accessor :owner
    def initialize(model, cursor, owner)
      super(model, cursor)
      @owner = owner
    end
  end
  class ObjCClassMethod < Function
    attr_accessor :owner
    def initialize(model, cursor, owner)
      super(model, cursor)
      @owner = owner
    end
  end

  class ObjCProperty < Entity
    attr_accessor :type, :owner, :getter, :setter
    def initialize(model, cursor, owner)
      super(model, cursor)
      @type = cursor.type
      @owner = owner
      @getter = nil
      @setter = nil
    end
    def is_readonly?
      @setter == nil
    end
    def types
      [@type]
    end
  end

  class ObjCClass < Entity
    attr_accessor :superclass, :protocols, :instance_vars, :class_vars, :instance_methods, :class_methods, :properties
    def initialize(model, cursor)
      super(model, cursor)
      @superclass = nil
      @protocols = []
      @instance_vars = []
      @class_vars = []
      @instance_methods = []
      @class_methods = []
      @properties = []
      @opaque = false
      @attributes = []
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_obj_c_class_ref
          @opaque = @name == cursor.spelling
        when :cursor_obj_c_super_class_ref
          @superclass = cursor.spelling
        when :cursor_obj_c_protocol_ref
          @protocols.push(cursor.spelling)
        when :cursor_obj_c_instance_var_decl
#          @instance_vars.push(ObjCInstanceVar.new(model, cursor))
        when :cursor_obj_c_class_var_decl
#          @class_vars.push(ObjCClassVar.new(model, cursor))
        when :cursor_obj_c_instance_method_decl
          @instance_methods.push(ObjCInstanceMethod.new(model, cursor, self))
        when :cursor_obj_c_class_method_decl
          @class_methods.push(ObjCClassMethod.new(model, cursor, self))
        when :cursor_obj_c_property_decl
          @properties.push(ObjCProperty.new(model, cursor, self))
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute)
            $stderr.puts "WARN: ObjC class #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in ObjC class at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end

      # Properties are alos represented as instance methods in the AST. Remove any instance method
      # defined on the same position as a property and use the method name as getter/setter.
      @instance_methods = @instance_methods - @instance_methods.find_all do |m|
        p = @properties.find {|f| f.id == m.id}
        if p
          if m.name =~ /.*:$/
            p.setter = m
          else
            p.getter = m
          end
          m
        else
          nil
        end
      end
    end

    def types
      (@instance_vars.map {|m| m.types} + @class_vars.map {|m| m.types} + @instance_methods.map {|m| m.types} + @class_methods.map {|m| m.types} + @properties.map {|m| m.types}).flatten
    end

    def is_opaque?
      @opaque
    end
  end

  class ObjCProtocol < Entity
    attr_accessor :protocols, :instance_methods, :class_methods, :properties
    def initialize(model, cursor)
      super(model, cursor)
      @protocols = []
      @instance_methods = []
      @class_methods = []
      @properties = []
      @opaque = false
      @attributes = []
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_obj_c_protocol_ref
          @opaque = @name == cursor.spelling
          @protocols.push(cursor.spelling)
        when :cursor_obj_c_instance_method_decl
          @instance_methods.push(ObjCInstanceMethod.new(model, cursor, self))
        when :cursor_obj_c_class_method_decl
          @class_methods.push(ObjCClassMethod.new(model, cursor, self))
        when :cursor_obj_c_property_decl
          @properties.push(ObjCProperty.new(model, cursor, self))
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute)
            $stderr.puts "WARN: ObjC protocol #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in ObjC protocol at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
    end

    def types
      (@instance_methods.map {|m| m.types} + @class_methods.map {|m| m.types} + @properties.map {|m| m.types}).flatten
    end

    def is_opaque?
      @opaque
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
      n = @name
      if @name.start_with?(@enum.prefix)
        n = @name[@enum.prefix.size..-1]
      end
      if /^[0-9].*/ =~ n
        n = "V#{n}"
      end
      n
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
    attr_accessor :conf, :typedefs, :functions, :objc_classes, :objc_protocols, :global_values, :constant_values, :structs, :enums, :cfenums, 
      :cfoptions, :conf_functions, :conf_values, :conf_constants, :conf_classes, :conf_protocols, :conf_enums
    def initialize(conf)
      @conf = conf
      @conf_typedefs = @conf['typedefs'] || {}
      @conf_enums = @conf['enums'] || {}
      @conf_functions = @conf['functions'] || {}
      @conf_values = conf['values'] || {}
      @conf_constants = conf['constants'] || {}
      @conf_classes = @conf['classes'] || {}
      @conf_protocols = @conf['protocols'] || {}
      @typedefs = []
      @functions = []
      @global_values = []
      @constant_values = []
      @structs = []
      @objc_classes = []
      @objc_protocols = []
      @enums = []
      @cfenums = [] # CF_ENUM(..., name) locations
      @cfoptions = [] # CF_OPTIONS(..., name) locations
      @type_cache = {}
    end
    def inspect
      object_id
    end
    def resolve_type_by_name(name)
      name = name.sub(/^(@ByVal|@Array.*)\s+/, '')
      e = Bro::builtins_by_name(name)
      e = e || @enums.find {|e| e.name == name}
      e = e || @structs.find {|e| e.name == name}
      e = e || @objc_classes.find {|e| e.name == name}
      e = e || @objc_protocols.find {|e| e.name == name}
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
        if type.pointee.kind == :type_unexposed && name.match(/\(\*\)/)
          # Callback. libclang does not expose info for callbacks.
          Bro::builtins_by_name('FunctionPtr')
        else
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
        end
      elsif type.kind == :type_record
        @structs.find {|e| e.name == name}
      elsif type.kind == :type_obj_c_object_pointer
        name = type.pointee.spelling
        if name =~ /^(id|NSObject)<(.*)>$/
          # Protocol
          name = $2
          e = @objc_protocols.find {|e| e.name == name}
          e && e.pointer
        else
          e = @objc_classes.find {|e| e.name == name}
          e && e.pointer
        end
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
          if td.is_callback? || td.is_struct? || td.is_enum?
            td
          else
            e = @enums.find {|e| e.name == name}
            e || resolve_type(td.typedef_type)
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

    def find_conf_matching(name, conf)
      match = conf.find {|pattern, value| name.match(pattern.sub(/^[+]/, "\\+"))}
      if !match
        nil
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
      conf[name] || find_conf_matching(name, conf)
    end
    def get_class_conf(name)
      get_conf_for_key(name, @conf_classes)
    end
    def get_function_conf(name)
      get_conf_for_key(name, @conf_functions)
    end
    def get_value_conf(name)
      get_conf_for_key(name, @conf_values)
    end
    def get_constant_conf(name)
      get_conf_for_key(name, @conf_constants)
    end
    def get_enum_conf(name)
      get_conf_for_key(name, @conf_enums)
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
          if cursor.spelling.to_s == "CF_ENUM" || cursor.spelling.to_s == "NS_ENUM"
            @cfenums.push Bro::location_to_id(cursor.location)
          elsif cursor.spelling.to_s == "CF_OPTIONS" || cursor.spelling.to_s == "NS_OPTIONS"
            @cfoptions.push Bro::location_to_id(cursor.location)
          end
          next :continue
        when :cursor_function
          @functions.push Function.new self, cursor
          next :continue
        when :cursor_variable
          @global_values.push GlobalValue.new self, cursor
          next :continue
        when :cursor_obj_c_interface_decl
          @objc_classes.push ObjCClass.new self, cursor
          next :continue
        when :cursor_obj_c_protocol_decl
          @objc_protocols.push ObjCProtocol.new self, cursor
          next :continue
        else
          next :recurse
        end
      end

      # Sort structs so that opaque structs come last. If a struct has a definition it should be used and not the forward declaration.
      @structs = @structs.sort {|a, b| (a.is_opaque? ? 1 : 0) <=> (b.is_opaque? ? 1 : 0) }.uniq {|e| e.name}.sort_by {|e| e.name}

      @objc_classes = @objc_classes.sort {|a, b| (a.is_opaque? ? 1 : 0) <=> (b.is_opaque? ? 1 : 0) }.uniq {|e| e.name}.sort_by {|e| e.name}
      @objc_protocols = @objc_protocols.sort {|a, b| (a.is_opaque? ? 1 : 0) <=> (b.is_opaque? ? 1 : 0) }.uniq {|e| e.name}.sort_by {|e| e.name}

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
    end
  end
end

sysroot = '/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.0.sdk'

def dump_ast(cursor, indent)
  cursor.visit_children do |cursor, parent|
    if cursor.kind != :cursor_macro_definition && cursor.kind != :cursor_macro_expansion && cursor.kind != :cursor_inclusion_directive
      puts "#{indent}#{cursor.kind} '#{cursor.spelling}' #{cursor.type.kind} '#{cursor.type.spelling}' '#{cursor.return_type.kind}' #{cursor.typedef_type ? cursor.typedef_type.kind : ''} #{Bro::location_to_s(cursor.location)}"
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
    if value
      template = template.gsub(/\/\*<#{key}>\*\/.*?\/\*<\/#{key}>\*\//m, "/*<#{key}>*/#{value}/*</#{key}>*/")
    end
  end
  open(target_file(dir, package, name), 'wb') do |f|
    f << template
  end
end

def struct_to_java(model, data, name, struct, conf)
  data = data || {}
  inc = struct.union ? 0 : 1
  index = 0
  members = []
  struct.members.each do |e|
    type = (conf[e.name] || {})['type'] || model.to_java_type(model.resolve_type(e.type))
    members.push(["@StructMember(#{index}) public native #{type} #{e.name}();", "@StructMember(#{index}) public native #{name} #{e.name}(#{type} #{e.name});"].join("\n    "))
    index = index + inc
  end
  members = members.join("\n    ")
  data['methods'] = "\n    #{members}\n    "

  constructor_params = []
  constructor_body = []
  struct.members.map do |e|
    type = (conf[e.name] || {})['type']
    type = type ? type.sub(/^(@ByVal|@Array.*)\s+/, '') : model.resolve_type(e.type).java_name
    constructor_params.push "#{type} #{e.name}"
    constructor_body.push "this.#{e.name}(#{e.name});"
  end.join("\n    ")
  constructor = "public #{name}(" + constructor_params.join(', ') + ") {\n        "
  constructor = constructor + constructor_body.join("\n        ")
  constructor = "#{constructor}\n    }"
  data['constructors'] = "\n    #{constructor}\n    "

  data['name'] = name
  data['visibility'] = conf['visibility'] || 'public'
  data['extends'] = "Struct<#{name}>"
  data['ptr'] = "public static class #{name}Ptr extends Ptr<#{name}, #{name}Ptr> {}"
  data
end

def opaque_to_java(model, data, name, struct, conf)
  data = data || {}
  data['name'] = name
  data['visibility'] = conf['visibility'] || 'public'
  data['extends'] = conf['extends'] || 'NativeObject'
  data['ptr'] = "public static class #{name}Ptr extends Ptr<#{name}, #{name}Ptr> {}"
  data
end

def property_to_java(model, prop, owner_conf)
  conf = get_conf_for_key(prop.name, owner_conf)
  name = conf['name'] || prop.name
  #name = name[0, 1].downcase + name[1..-1]
  getter = "get#{name[0, 1].upcase + name[1..-1]}"
  setter = "set#{name[0, 1].upcase + name[1..-1]}"
  java_type = conf['type'] || model.to_java_type(model.resolve_type(prop.type))
  visibility = conf['visibility'] || 'public'
  native = prop.owner.is_a?(Bro::ObjCClass) ? " native" : ""
  lines = ["@Property(getter = \"#{prop.getter.name}\")", "#{visibility}#{native} #{java_type} #{getter}();"]
  if !prop.is_readonly? && !conf['readonly']
    lines = lines + ["@Property(setter = \"#{prop.setter.name}\")", "#{visibility}#{native} void #{setter}(#{java_type} v);"]
  end
  lines
end

def method_to_java(model, method, owner_conf)
  conf = get_conf_for_key((method.is_a?(Bro::ObjCClassMethod) ? '+' : '-') + method.name, owner_conf)
  name = conf['name'] || method.name
  java_type = conf['type'] || model.to_java_type(model.resolve_type(method.return_type))
  visibility = conf['visibility'] || 'public'
  native = method.owner.is_a?(Bro::ObjCClass) ? "native " : ""
  static = method.is_a?(Bro::ObjCClassMethod) ? "static " : ""
  lines = ["@Method", "#{visibility} #{static}#{native}#{java_type} #{name}();"]
  lines
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
    # Excluded all classes in included config
    c_classes = (c['classes'] || {}).inject({}) {|h, (k, v)| v = v || {}; v['exclude'] = true; h[k] = v; h}
    conf['classes'] = c_classes.merge(conf['classes'] || {})
    conf['enums'] = (c['enums'] || {}).merge(conf['enums'] || {})
    conf['typedefs'] = (c['typedefs'] || {}).merge(conf['typedefs'] || {})
  end

  index = FFI::Clang::Index.new
  clang_args = ['-arch', 'armv7', '-mthumb', '-miphoneos-version-min', '7.0', '-fblocks', '-isysroot', sysroot]
  if conf['clang_args']
    clang_args = clang_args + conf['clang_args']
  end
  #translation_unit = index.parse_translation_unit(header, ['-arch', 'armv7', '-mthumb', '-miphoneos-version-min', '7.0', '-fblocks', '-x', 'objective-c', '-isysroot', sysroot], [], {:detailed_preprocessing_record=>true})
  translation_unit = index.parse_translation_unit("#{sysroot}#{header}", clang_args, [], {:detailed_preprocessing_record=>true})
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

  potential_constant_enums = []
  model.enums.each do |enum|
    c = model.get_enum_conf(enum.name)
    if c && !c['exclude']
      data = {}
      java_name = enum.java_name
      bits = enum.is_options? || c['bits']
      if bits
        values = enum.values.map { |e| "public static final #{java_name} #{e.java_name} = new #{java_name}(#{e.value})" }.join(";\n    ") + ";"
      else
        values = enum.values.map { |e| "#{e.java_name}(#{e.value})" }.join(",\n    ") + ";"
      end
      data['values'] = "\n    #{values}\n    "
      data['name'] = java_name
      if c['marshaler']
        data['annotations'] = "@Marshaler(#{c['marshaler']}.class)"
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
    else
      # Possibly an enum with values that should be turned into constants
      potential_constant_enums.push(enum)
    end
  end

  template_datas = {}

  model.structs.find_all {|e| e.name.size > 0 }.each do |struct|
    c = model.get_class_conf(struct.name)
    if c && !c['exclude']
      name = c['name'] || struct.name
      template_datas[name] = struct.is_opaque? ? opaque_to_java(model, {}, name, struct, c) : struct_to_java(model, {}, name, struct, c)
    end
  end
  model.typedefs.find_all {|e| e.struct && !e.struct.is_opaque? }.each do |td|
    c = model.get_class_conf(td.name)
    if c && !c['exclude']
      puts "#{td.name} #{td.struct}"
      name = c['name'] || td.name
      template_datas[name] = struct_to_java(model, {}, name, td.struct, c)
    end
  end

  # conf_structs = conf['structs'] || {}
  # model.referenced_structs.each do |pair|
  #   td = pair[0]
  #   struct = pair[1]

  #   data = template_datas[td.java_name] || {}
  #   sconf = get_conf_for_key(td.java_name, conf_structs) 

  #   inc = struct.union ? 0 : 1
  #   index = 0
  #   members = []
  #   struct.members.each do |e|
  #     type = (sconf[e.name] || {})['type'] || model.to_java_type(model.resolve_type(e.type))
  #     members.push(["@StructMember(#{index}) public native #{type} #{e.name}();", "@StructMember(#{index}) public native #{td.java_name} #{e.name}(#{type} #{e.name});"].join("\n    "))
  #     index = index + inc
  #   end
  #   members = members.join("\n    ")
  #   data['methods'] = "\n    #{members}\n    "

  #   constructor_params = []
  #   constructor_body = []
  #   struct.members.map do |e|
  #     type = (sconf[e.name] || {})['type']
  #     type = type ? type.sub(/^(@ByVal|@Array.*)\s+/, '') : model.resolve_type(e.type).java_name
  #     constructor_params.push "#{type} #{e.name}"
  #     constructor_body.push "this.#{e.name}(#{e.name});"
  #   end.join("\n    ")
  #   constructor = "public #{td.java_name}(" + constructor_params.join(', ') + ") {\n        "
  #   constructor = constructor + constructor_body.join("\n        ")
  #   constructor = "#{constructor}\n    }"
  #   data['constructors'] = "\n    #{constructor}\n    "

  #   data['name'] = td.java_name
  #   data['visibility'] = sconf['visibility'] || 'public'
  #   data['extends'] = "Struct<#{td.java_name}>"
  #   data['imports'] = imports_s
  #   data['ptr'] = "public static class Ptr extends org.robovm.rt.bro.ptr.Ptr<#{td.java_name}, Ptr> {}"

  #   template_datas[td.java_name] = data
  # end

  # model.referenced_opaques.each do |pair|
  #   td = pair[0]
  #   c = model.conf_classes[td.name] || {}
  #   name = c['name'] || td.java_name
  #   data = template_datas[name] || {}
  #   data['name'] = name
  #   data['visibility'] = c['visibility'] || 'public'
  #   data['extends'] = c['extends'] || data['extends'] || 'NativeObject'
  #   data['imports'] = imports_s
  #   data['ptr'] = "public static class Ptr extends org.robovm.rt.bro.ptr.Ptr<#{td.java_name}, Ptr> {}"
  #   template_datas[name] = data
  # end

  # model.objc_classes.find_all {|cls| !cls.is_opaque?} .each do |cls|
  #   c = model.conf_classes[cls.name] || {}
  #   name = c['name'] || cls.java_name
  #   data = template_datas[name] || {}
  #   data['name'] = name
  #   data['visibility'] = c['visibility'] || 'public'
  #   data['extends'] = c['extends'] || (cls.superclass && (model.conf_classes[cls.superclass] || {})['name'] || cls.superclass) || 'ObjCObject'
  #   data['imports'] = imports_s
  #   data['implements'] = cls.protocols.empty? && '' || ("implements " + cls.protocols.map {|e| (model.conf_protocols[e] || {})['name'] || e}.join(', '))
  #   data['properties'] = cls.properties.map {|p| property_to_java(model, p, c['properties'] || {})}.flatten.join("\n    ")
  #   data['methods'] = cls.instance_methods.map {|m| method_to_java(model, m, c['methods'] || {})}.flatten.join("\n    ")
  #   data['ptr'] = "public static class Ptr extends org.robovm.rt.bro.ptr.Ptr<#{cls.java_name}, Ptr> {}"
  #   template_datas[name] = data
  # end

  # model.objc_protocols.each do |prot|
  #   c = model.conf_protocols[prot.name] || {}
  #   name = c['name'] || prot.java_name
  #   data = template_datas[name] || {}
  #   data['name'] = name
  #   data['visibility'] = c['visibility'] || 'public'
  #   data['implements'] = prot.protocols.empty? && '' || ("extends " + prot.protocols.map {|e| (model.conf_protocols[e] || {})['name'] || e}.join(', '))
  #   data['imports'] = imports_s
  #   #data['ptr'] = "public static class Ptr extends org.robovm.rt.bro.ptr.Ptr<#{prot.java_name}, Ptr> {}"
  #   data['template'] = def_protocol_template
  #   template_datas[name] = data
  # end

  # Assign global values to classes
  values = {}
  model.global_values.each do |v|
    vconf = model.get_value_conf(v.name)
    if vconf && !vconf['exclude']
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
  functions = {}
  model.functions.each do |f|
    fconf = model.get_function_conf(f.name)
    if fconf && !fconf['exclude']
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
  constants = {}
  model.constant_values.each do |v|
    vconf = model.get_constant_conf(v.name)
    if vconf && !vconf['exclude']
      owner = vconf['class'] || default_class
      constants[owner] = (constants[owner] || []).push([v, vconf])
    end
  end
  # Create ConstantValues for values in remaining enums
  potential_constant_enums.each do |enum|
    type = [:type_longlong, :type_ulonglong].include?(enum.enum_type.kind) ? 'long' : 'int'
    enum.type.declaration.visit_children do |cursor, parent|
      case cursor.kind
      when :cursor_enum_constant_decl
        name = cursor.spelling
        value = cursor.enum_value
        if type == 'long'
          value = "#{value}L"
        end
        c = model.get_constant_conf(name)
        if c && !c['exclude']
          owner = c['class'] || default_class
          v = Bro::ConstantValue.new model, cursor, value, type
          constants[owner] = (constants[owner] || []).push([v, c])
        end
      end
      next :continue
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
    c = model.get_class_conf(owner) || {}
    data['imports'] = imports_s
    data['extends'] = data['extends'] || c['extends'] || nil
    merge_template(target_dir, package, owner, data['template'] || def_class_template, data)
  end

  #puts model.constant_values.map { |e| "#{e.name} = #{e.value} (#{e.framework})" }

end
