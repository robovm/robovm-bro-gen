#!/usr/bin/env ruby

# Copyright (C) 2014 Trillian Mobile AB
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/gpl-2.0.html>.
#

$LOAD_PATH.unshift File.dirname(__FILE__) + "/ffi-clang/lib"

require "ffi/clang"
require 'yaml'
require 'fileutils'
require 'pathname'

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
    @@deprecated_version = 5
  
    attr_accessor :id, :location, :name, :framework, :attributes
    def initialize(model, cursor)
      @location = cursor ? cursor.location : nil
      @id = cursor ? Bro::location_to_id(@location) : nil
      @name = cursor ? cursor.spelling : nil
      @model = model
      @framework = @location ?
          "#{@location.file}".split(File::SEPARATOR).reverse.find_all {|e| e.match(/^.*\.framework$/)}.map {|e| e.sub(/(.*)\.framework/, '\1')}.first :
          nil
      @attributes = []
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

    def is_available?(mac_version, ios_version)
      attrib = @attributes.find {|e| e.is_a?(AvailableAttribute)}
      if attrib
        mac_version && attrib.mac_version && attrib.mac_version.to_f <= mac_version.to_f ||
          ios_version && attrib.ios_version && attrib.ios_version.to_f <= ios_version.to_f || false
      else
        true
      end
    end
    
    def is_outdated?
      if deprecated
        d_version = deprecated[0..2].to_f
  	    d_version <= @@deprecated_version
      else
        false
      end
    end

    def since
      attrib = @attributes.find {|e| e.is_a?(AvailableAttribute)}
      if attrib
        attrib.ios_version
      else
        nil
      end
    end

    def deprecated
      attrib = @attributes.find {|e| e.is_a?(AvailableAttribute)}
      if attrib
        attrib.ios_dep_version
      else
        nil
      end
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

  class Block < Entity
    attr_accessor :return_type, :param_types
    def initialize(return_type, param_types)
      super(nil, nil)
      @return_type = return_type
      @param_types = param_types
    end
    def types
      [@return_type.types] + @param_types.map {|e| e.types}
    end
    def java_name
      if @return_type.is_a?(Builtin) && @return_type.name == 'void' && @param_types.empty?
        "@Block Runnable"
      elsif @return_type.is_a?(Builtin) && @return_type.name == 'void' && 
            @param_types.size == 1 && @param_types[0].is_a?(Builtin) && @param_types[0].name == 'boolean'
        "@Block VoidBooleanBlock"
      else
        "ObjCBlock"
      end
    end
  end

  class ObjCId < Entity
    attr_accessor :protocols
    def initialize(protocols)
      super(nil, nil)
      @protocols = protocols
    end
    def types
      @protocols.map {|e| e.types}
    end
    def java_name
      @protocols.map {|e| e.java_name}.join(' & ')
    end
  end

  class Builtin < Entity
    attr_accessor :name, :type_kinds, :java_name
    def initialize(name, type_kinds = [], java_name = nil)
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
    Builtin.new('String', [], 'String'),
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
    attr_accessor :mac_version, :ios_version, :mac_dep_version, :ios_dep_version
    def initialize(source)
      super(source)
      s = source.sub(/^[A-Z_]+\s*\(/, '')
      s = s.sub(/\)$/, '')
      args = s.split(/\s*,\s*/)
      @mac_version = nil
      @ios_version = nil
      @mac_dep_version = nil
      @ios_dep_version = nil
      args = args.map {|e| e.sub(/^[A-Z_]+/, '')}
      args = args.map {|e| e.gsub(/_/, '.')}
      if source.match(/_AVAILABLE_IOS\s*\(/)
        @ios_version = args[0]
      elsif source.match(/_AVAILABLE_MAC\s*\(/)
        @mac_version = args[0]
      elsif source.match(/_AVAILABLE\s*\(/)
        if args.length == 1
          # E.g. MP_EXTERN_CLASS_AVAILABLE(version) = NS_CLASS_AVAILABLE(NA, version).
          # Just set both versions to the specified value
          @mac_version = @ios_version = args[0]
        else
          @mac_version = args[0]
          @ios_version = args[1]
        end
      elsif source.match(/_DEPRECATED_MAC\s*\(/)
        @mac_version = args[0]
        @mac_dep_version = args[1]
      elsif source.match(/_DEPRECATED_IOS\s*\(/)
        @ios_version = args[0]
        @ios_dep_version = args[1]
      elsif source.match(/_AVAILABLE_STARTING\s*\(/)
        @mac_version = args[0]
        @ios_version = args[1]
      elsif source.match(/_AVAILABLE_BUT_DEPRECATED\s*\(/)
        @mac_version = args[0]
        @mac_dep_version = args[1]
        @ios_version = args[2]
        @ios_dep_version = args[3]
      elsif source.match(/_DEPRECATED\s*\(/)
        @mac_version = args[0]
        @mac_dep_version = args[1]
        @ios_version = args[2]
        @ios_dep_version = args[3]
      end
      @mac_version = @mac_version == '' ? nil : @mac_version
      @mac_dep_version = @mac_version == '' ? nil : @mac_dep_version
      @ios_version = @ios_version == '' ? nil : @ios_version
      @ios_dep_version = @ios_version == '' ? nil : @ios_dep_version
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
       source == 'NS_RETURNS_INNER_POINTER' || source == 'NS_AUTOMATED_REFCOUNT_WEAK_UNAVAILABLE' || source == 'NS_REQUIRES_NIL_TERMINATION' ||
       source == 'NS_ROOT_CLASS' || source == '__header_always_inline' || source.end_with?('_EXTERN') || source.end_with?('_EXTERN_CLASS') ||
       source.end_with?('_CLASS_EXPORT') || source.end_with?('_EXPORT') || source == 'NS_REPLACES_RECEIVER' || source == '__objc_exception__' || source == 'OBJC_EXPORT' ||
       source == 'OBJC_ROOT_CLASS' || source == '__ai' || source.end_with?('_EXTERN_WEAK')
      return IgnoredAttribute.new source
    elsif source == 'NS_UNAVAILABLE' || source == 'UNAVAILABLE_ATTRIBUTE'
      return UnavailableAttribute.new source
    elsif source.match(/_AVAILABLE/) || source.match(/_DEPRECATED/) ||
          source.match(/_AVAILABLE_STARTING/) || source.match(/_AVAILABLE_BUT_DEPRECATED/)
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
          if cursor.type.kind == :type_record && @typedef_type.kind != :type_pointer
            @struct = Struct.new model, cursor, nil, cursor.spelling.match(/\bunion\b/)
          end
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
      @name = @name.gsub(/\s*\bconst\b\s*/, '')
      @name = @name.sub(/^(struct|union)\s*/, '')
      @members = []
      @children = []
      @parent = parent
      @union = union
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_unexposed_expr
        	# ignored
        when :cursor_field_decl
          @members.push StructMember.new cursor
        when :cursor_struct, :cursor_union
          s = Struct.new model, cursor, self, cursor.kind == :cursor_union
          model.structs.push s
          @children.push s
        when :cursor_unexposed_attr, :cursor_packed_attr, :cursor_annotate_attr
          a = Bro::read_attribute(cursor)
          if a != '?' && model.is_included?(self)
            $stderr.puts "WARN: #{@union ? 'union' : 'struct'} #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute #{a}"
          end
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
      param_count = 0
      @inline = false
      @variadic = cursor.variadic?
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_type_ref, :cursor_obj_c_class_ref, :cursor_obj_c_protocol_ref, :cursor_unexposed_expr, :cursor_ibaction_attr
          # Ignored
        when :cursor_parm_decl
          @parameters.push FunctionParameter.new cursor, "p#{param_count}"
          param_count = param_count + 1
        when :cursor_compound_stmt
          @inline = true
        when :cursor_asm_label_attr, :cursor_unexposed_attr, :cursor_annotate_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
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
      @variadic
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
  class ObjCMethod < Function
    attr_accessor :owner
    def initialize(model, cursor, owner)
      super(model, cursor)
      @owner = owner
    end
  end
  class ObjCInstanceMethod < ObjCMethod
    def initialize(model, cursor, owner)
      super(model, cursor, owner)
    end
  end
  class ObjCClassMethod < ObjCMethod
    def initialize(model, cursor, owner)
      super(model, cursor, owner)
    end
  end

  class ObjCProperty < Entity
    attr_accessor :type, :owner, :getter, :setter, :attrs
    def initialize(model, cursor, owner)
      super(model, cursor)
      @type = cursor.type
      @owner = owner
      @getter = nil
      @setter = nil
      @source = Bro::read_source_range(cursor.extent)
      /@property\s*(\((?:[^)]+)\))/ =~ @source
      @attrs = $1 != nil ? $1.strip.slice(1..-2).split(/,\s*/) : []
      @attrs = @attrs.inject(Hash.new) do |h, o|
        pair = o.split(/\s*=\s*/)
        h[pair[0]] = pair.size > 1 ? pair[1] : true
        h
      end
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_type_ref, :cursor_parm_decl, :cursor_obj_c_class_ref, :cursor_obj_c_protocol_ref, :cursor_obj_c_instance_method_decl, :cursor_iboutlet_attr, :cursor_annotate_attr, :cursor_unexposed_expr
          # Ignored
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
            $stderr.puts "WARN: ObjC property #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in ObjC property #{@name} at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
    end
    def getter_name
      @attrs['getter'] || @name
    end
    def setter_name
      base = @name[0, 1].upcase + @name[1..-1]
      @attrs['setter'] || "set#{base}:"
    end
    def is_readonly?
      @setter == nil && @attrs['readonly']
    end
    def types
      [@type]
    end
  end

  class ObjCMemberHost < Entity
    attr_accessor :instance_methods, :class_methods, :properties
    def initialize(model, cursor)
      super(model, cursor)
      @instance_methods = []
      @class_methods = []
      @properties = []
    end

    def resolve_property_accessors
      # Properties are also represented as instance methods in the AST. Remove any instance method
      # defined on the same position as a property and use the method name as getter/setter.
      @instance_methods = @instance_methods - @instance_methods.find_all do |m|
        p = @properties.find {|f| f.id == m.id || f.getter_name == m.name || f.setter_name == m.name}
        if p
          if m.name.end_with?(':')
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
  end

  class ObjCClass < ObjCMemberHost
    attr_accessor :superclass, :protocols, :instance_vars, :class_vars
    def initialize(model, cursor)
      super(model, cursor)
      @superclass = nil
      @protocols = []
      @instance_vars = []
      @class_vars = []
      @opaque = false
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_unexposed_expr
        	# ignored
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
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
            $stderr.puts "WARN: ObjC class #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in ObjC class at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
      resolve_property_accessors
    end

    def types
      (@instance_vars.map {|m| m.types} + @class_vars.map {|m| m.types} + @instance_methods.map {|m| m.types} + @class_methods.map {|m| m.types} + @properties.map {|m| m.types}).flatten
    end

    def is_opaque?
      @opaque
    end
  end

  class ObjCProtocol < ObjCMemberHost
    attr_accessor :protocols, :owner
    def initialize(model, cursor)
      super(model, cursor)
      @protocols = []
      @opaque = false
      @owner = nil
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_unexposed_expr
        	# ignored
        when :cursor_obj_c_protocol_ref
          @opaque = @name == cursor.spelling
          @protocols.push(cursor.spelling)
        when :cursor_obj_c_class_ref
          @owner = cursor.spelling
        when :cursor_obj_c_instance_method_decl
          @instance_methods.push(ObjCInstanceMethod.new(model, cursor, self))
        when :cursor_obj_c_class_method_decl
          @class_methods.push(ObjCClassMethod.new(model, cursor, self))
        when :cursor_obj_c_property_decl
          @properties.push(ObjCProperty.new(model, cursor, self))
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
            $stderr.puts "WARN: ObjC protocol #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in ObjC protocol at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
      resolve_property_accessors
    end

    def is_informal?
      !!@owner
    end

    def types
      (@instance_methods.map {|m| m.types} + @class_methods.map {|m| m.types} + @properties.map {|m| m.types}).flatten
    end

    def is_opaque?
      @opaque
    end

    def java_name
      name ? ((@model.get_protocol_conf(name) || {})['name'] || name) : ''
    end
  end

  class ObjCCategory < ObjCMemberHost
    attr_accessor :owner, :protocols
    def initialize(model, cursor)
      super(model, cursor)
      @protocols = []
      @owner = nil
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_unexposed_expr
        	# ignored
        when :cursor_obj_c_class_ref
          @owner = cursor.spelling
        when :cursor_obj_c_protocol_ref
          @protocols.push(cursor.spelling)
        when :cursor_obj_c_instance_method_decl
          @instance_methods.push(ObjCInstanceMethod.new(model, cursor, self))
        when :cursor_obj_c_class_method_decl
          @class_methods.push(ObjCClassMethod.new(model, cursor, self))
        when :cursor_obj_c_property_decl
          @properties.push(ObjCProperty.new(model, cursor, self))
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
            $stderr.puts "WARN: ObjC category #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in ObjC category at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
      resolve_property_accessors
    end

    def java_name
      #name ? ((@model.get_category_conf(name) || {})['name'] || name) : ''
      "#{@owner}Extensions"
    end

    def types
      (@instance_vars.map {|m| m.types} + @class_vars.map {|m| m.types} + @instance_methods.map {|m| m.types} + @class_methods.map {|m| m.types} + @properties.map {|m| m.types}).flatten
    end
  end

  class GlobalValueDictionaryWrapper < Entity
    attr_accessor :name, :values
    def initialize(model, name, enum, first)
      super(model, nil)
      @name = name
      @enum = enum
      @type = first.type
      vconf = model.get_value_conf(first.name)
      @java_type = vconf['type'] || model.resolve_type(@type)
      @mutable = vconf['mutable'] || true
      @methods = vconf['methods']
      @extends = vconf['extends'] || is_foundation? ? "NSDictionaryWrapper" : "CFDictionaryWrapper"
      @constructor_visibility = vconf['constructor_visibility']
      @values = [first]
    end
    
    def is_foundation?
      !["CFString", "CFNumber"].include? @java_type 
    end
    
    def is_mutable?
      @mutable
    end
    
    def generate_template_data(data)
      data['name'] = @name
      data['extends'] = @extends
      data['annotations'] = (data['annotations'] || []).push("@Library(\"#{@@library}\")")
    
      marshaler_lines = []
      append_marshalers(marshaler_lines)
      marshalers_s = marshaler_lines.flatten.join("\n    ")
      data['marshalers'] = "\n    #{marshalers_s}\n    "
    
      constructor_lines = []
      append_constructors(constructor_lines)
      constructors_s = constructor_lines.flatten.join("\n    ")
      data['constructors'] = "\n    #{constructors_s}\n    "
    
      method_lines = []
      append_basic_methods(method_lines)
      append_convenience_methods(method_lines) if !@methods.nil?
	  methods_s = method_lines.flatten.join("\n    ")
      data['methods'] = "\n    #{methods_s}\n    "
    
      if @enum.nil?
        key_lines = []
        append_key_class(key_lines)
        keys_s = key_lines.flatten.join("\n    ")
        data['keys'] = "\n    #{keys_s}\n    "
      end
    
      data
    end
    
    def append_marshalers(lines)
      dict_type = is_foundation? ? "NSDictionary" : "CFDictionary"
      dict_generics = is_foundation? ? "<NSString, NSObject>" : ""
      base_type = is_foundation? ? "NSObject" : "CFType"
    
      lines << "public static class Marshaler {"
      lines << "    @MarshalsPointer"
      lines << "    public static #{@name} toObject(Class<#{@name}> cls, long handle, long flags) {"
      lines << "        #{dict_type}#{dict_generics} o = (#{dict_type}#{dict_generics}) #{base_type}.Marshaler.toObject(#{dict_type}.class, handle, flags);"
      lines << "        if (o == null) {"
      lines << "            return null;"
      lines << "        }"
      lines << "        return new #{name}(o);"
      lines << "    }"
      lines << "    @MarshalsPointer"
      lines << "    public static long toNative(#{name} o, long flags) {"
      lines << "        if (o == null) {"
      lines << "            return 0L;"
      lines << "        }"
      lines << "        return #{base_type}.Marshaler.toNative(o.data, flags);"
      lines << "    }"
      lines << "}"
    
      array_type = is_foundation? ? "NSArray<#{dict_type}#{dict_generics}>" : "CFArray"
    
      lines << "public static class AsListMarshaler {"
      lines << "    @MarshalsPointer"
      lines << "    public static List<#{@name}> toObject(Class<? extends #{base_type}> cls, long handle, long flags) {"
      lines << "        #{array_type} o = (#{array_type}) #{base_type}.Marshaler.toObject(cls, handle, flags);"
      lines << "        if (o == null) {"
      lines << "            return null;"
      lines << "        }"
      lines << "        List<#{@name}> list = new ArrayList<>();"
      lines << "        for (int i = 0; i < o.size(); i++) {"
      lines << "            list.add(new #{@name}(o.get(i)));" if is_foundation?
      lines << "            list.add(new #{@name}(o.get(i, CFDictionary.class)));" if !is_foundation?
      lines << "        }"
      lines << "        return list;"
      lines << "    }"
      lines << "    @MarshalsPointer"
      lines << "    public static long toNative(List<#{@name}> l, long flags) {"
      lines << "        if (l == null) {"
      lines << "            return 0L;"
      lines << "        }"
      lines << "        NSArray<NSDictionary<NSString, NSObject> array = new NSMutableArray<>();" if is_foundation?
      lines << "        CFArray array = CFMutableArray.create();" if !is_foundation?
      lines << "        for (#{@name} i : l) {"
      lines << "            array.add(i.getDictionary());"
      lines << "        }"
      lines << "        return #{base_type}.Marshaler.toNative(array, flags);"
      lines << "    }"
      lines << "}"
    end
    
    def append_constructors(lines)
      dict_type = is_foundation? ? "NSDictionary<NSString, NSObject>" : "CFDictionary"
    
      constructor_visibility = "#{@constructor_visibility} " || ''
    
      lines << "#{constructor_visibility}#{@name}(#{dict_type} data) {"
      lines << "    super(data);"
      lines << "}"
      lines << "public #{@name}() {}" if is_mutable?
    end
    
    def append_basic_methods(lines)
      key_type = @enum ? @enum.name : @java_type
      key_value = @enum ? "key.value()" : "key"
      base_type = is_foundation? ? "NSObject" : "NativeObject"
    
      lines << "public boolean has(#{key_type} key) {"
      lines << "    return data.containsKey(#{key_value});"
      lines << "}"
      lines << "public NSObject get(#{key_type} key) {" if is_foundation?
      lines << "public <T extends NativeObject> T get(#{key_type} key, Class<T> type) {" if !is_foundation?
      lines << "    if (has(key)) {"
      lines << "        return data.get(#{key_value});" if is_foundation?
      lines << "        return data.get(#{key_value}, type);" if !is_foundation?
      lines << "    }"
      lines << "    return null;"
      lines << "}"
      lines << "public #{@name} set(#{key_type} key, #{base_type} value) {"
      lines << "    data.put(#{key_value}, value);"
      lines << "    return this;"
      lines << "}"
    end
    
    def append_convenience_methods(lines)
      lines << "\n"
      @values.find_all {|v| v.is_available?(@@mac_version, @@ios_version) && !v.is_outdated?}.each do |v|
          vconf = @model.get_value_conf(v.name)
          vname = vconf['name'] || v.name
          method = @methods.detect {|m| vname == m[0] || v.name == m[0] }
          if method
            mconf = method[1]
            name = mconf['name'] || method[0]
            param_name = name[0].downcase + name[1..-1]
            omit_prefix = mconf['omit_prefix'] || false
            type = mconf['type'] || 'boolean'
            
            getter = @model.getter_for_name(param_name, type, omit_prefix)
            
            default_value = mconf['default'] || default_value_for_type(type)
            key_accessor = @enum ? "#{@enum.name}.#{vname}" : "Keys.#{vname}()"
            
            @model.push_availability(v, lines)
            lines << "public #{type} #{getter}() {"
            lines << "    if (has(#{key_accessor})) {"
            lines << convenience_getter_value(type, key_accessor)
            lines << "    }"
            lines << "    return #{default_value};"
            lines << "}"

            if is_mutable?
              setter = @model.setter_for_name(name, omit_prefix)
              
			  @model.push_availability(v, lines)
			  lines << "public #{@name} #{setter}(#{type} #{param_name}) {"
			  lines << "    set(#{key_accessor}, #{convenience_setter_value(type, param_name)});"
			  lines << "    return this;"
			  lines << "}"
			end
          end
      end
    end
    
    def convenience_getter_value(type, key_accessor)
      s = []
      resolved_type = @model.resolve_type_by_name(type)
      
      type_no_generics = type.partition("<").first
      
      if is_foundation?
        case type
          when 'boolean', 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
            s << "NSNumber val = (NSNumber) get(#{key_accessor});"
            s << "return val.#{type}Value();"
          when 'String'
            s << "NSString val = (NSString) get(#{key_accessor});"
            s << "return val.toString();"
          else
            s << "#{type} val = get(#{key_accessor}, #{type_no_generics}.class);"
            s << "return val;"
        end
      else
        if resolved_type.is_a?(GlobalValueEnumeration)
          s << "#{resolved_type.java_type} val = get(#{key_accessor}, #{resolved_type.java_type}.class);"
          s << "return #{resolved_type.name}.valueOf(val);"
        elsif resolved_type.is_a?(GlobalValueDictionaryWrapper)
          s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
          s << "return new #{resolved_type.name}(val);"
        elsif resolved_type.is_a?(Enum)
          s << "CFNumber val = get(#{key_accessor}, CFNumber.class);"
          econf = @model.get_enum_conf(resolved_type.name)
          if resolved_type.is_options? || econf['bits']
            s << "return new #{resolved_type.name}(val.longValue());"
          else
            s << "return #{resolved_type.name}.valueOf(val.longValue());"
          end
        else
        case type
          when 'boolean'
            s << "CFBoolean val = get(#{key_accessor}, CFBoolean.class);"
            s << "return val.booleanValue();"
          when 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
            s << "CFNumber val = get(#{key_accessor}, CFNumber.class);"
            s << "return val.#{type}Value();"
          when 'String'
            s << "CFString val = get(#{key_accessor}, CFString.class);"
            s << "return val.toString();"
          when 'CMTime'
            s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
            s << "NSDictionary dict = val.as(NSDictionary.class);"
            s << "return CMTime.create(dict);"
          when 'Map<String, NSObject>'
            s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
            s << "NSDictionary dict = val.as(NSDictionary.class);"
            s << "return dict.asStringMap();"
          when 'Map<String, String>'
            s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
            s << "return val.asStringStringMap();"
          else
            s << "#{type} val = get(#{key_accessor}, #{type_no_generics}.class);"
            s << "return val;"
        end
        end
      end
      "        " + s.flatten.join("\n            ")
    end
    
    def convenience_setter_value(type, param_name)
      s = ''
      resolved_type = @model.resolve_type_by_name(type)
      if is_foundation?
        case type
          when 'boolean'
            s
        end
      else
        if resolved_type.is_a?(GlobalValueEnumeration)
          s = "#{param_name}.value()"
        elsif resolved_type.is_a?(GlobalValueDictionaryWrapper)
          s = "#{param_name}.getDictionary()"
        elsif resolved_type.is_a?(Enum)
          s = "CFNumber.valueOf(#{param_name}.value())"
        else
        case type
          when 'boolean'
            s = "CFBoolean.valueOf(#{param_name})"
          when 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
            s = "CFNumber.valueOf(#{param_name})"
          when 'String'
            s = "new CFString(#{param_name})"
          when 'CMTime'
            s = "#{param_name}.asDictionary(null).as(CFDictionary.class)"
          when 'Map<String, NSObject>'
            s = "CFDictionary.fromStringMap(#{param_name})"
          when 'Map<String, String>'
            s = "CFDictionary.fromStringStringMap(#{param_name})"
          else
            s = param_name
        end
        end
      end
      s
    end
    
    def default_value_for_type(type)
      default = 'null'
      case type
      when 'boolean'
        default = false
      when 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
        default = 0
      end
      default
    end
    
    def append_key_class(lines)
      @values.sort_by { |v| v.since }
      
      lines << "@Library(\"#{@@library}\")"
      lines << "public static class Keys {"
      lines << "    static { Bro.bind(Keys.class); }"
    	
      @values.find_all {|v| v.is_available?(@@mac_version, @@ios_version) && !v.is_outdated?}.each do |v|
        vconf = @model.get_value_conf(v.name)
      
        indentation = "    "
        vname = vconf['name'] || v.name
        java_type = vconf['type'] || @model.to_java_type(@model.resolve_type(v.type, true))
        visibility = vconf['visibility'] || 'public'
            
        @model.push_availability(v, lines, indentation)
        if vconf.has_key?('dereference') && !vconf['dereference']
          lines << "#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true, dereference=false)"
        else
          lines << "#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)"
        end
        lines << "#{indentation}#{visibility} static native #{java_type} #{vname}();"
      end
      
      lines << "}"
    end
    
    private :append_marshalers, :append_constructors, :append_basic_methods, :append_convenience_methods, :append_key_class
  end

  class GlobalValueEnumeration < Entity
    attr_accessor :name, :type, :java_type, :values
    def initialize(model, name, first)
      super(model, nil)
      @name = name
      @type = first.type
      vconf = model.get_value_conf(first.name)
      @java_type = vconf['type'] || model.resolve_type(@type)
      @values = [first]
    end
  end

  class GlobalValue < Entity
    attr_accessor :type, :enum, :dictionary
    def initialize(model, cursor)
      super(model, cursor)
      @type = cursor.type
      
      conf = model.get_value_conf(name)
      @enum = conf ? conf['enum'] : nil
      @dictionary = conf ? conf['dictionary'] : nil
      
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_type_ref, :cursor_integer_literal, :cursor_asm_label_attr, :cursor_obj_c_class_ref, :cursor_obj_c_protocol_ref, :cursor_unexposed_expr
          # Ignored
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
            $stderr.puts "WARN: Global value #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          raise "Unknown cursor kind #{cursor.kind} in global value #{@name} at #{Bro::location_to_s(@location)}"
        end
        next :continue
      end
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

  class EnumValue < Entity
    attr_accessor :name, :value, :type, :enum
    def initialize(model, cursor, enum)
      super(model, cursor)
      @name = cursor.spelling
      @value = cursor.enum_value
      @type = cursor.type
      @enum = enum
      @java_name = nil
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
            $stderr.puts "WARN: Enum value #{@name} at #{Bro::location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
          end
          @attributes.push attribute
        else
          # Ignored
        end
        next :continue
      end
    end
    def java_name
      if @java_name
        @java_name
      else
        n = @enum.enum_conf[@name] || @name
        if n.start_with?(@enum.prefix)
          n = @name[@enum.prefix.size..-1]
        end
        if n.end_with?(@enum.suffix)
          n = n[0..(n.size - @enum.suffix.size - 1)]
        end
        if n[0] >= '0' && n[0] <= '9'
          n = "_#{n}"
        end
        @java_name = n
        n
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
      @enum_conf = nil
      cursor.visit_children do |cursor, parent|
        case cursor.kind
        when :cursor_enum_constant_decl
          values.push EnumValue.new model, cursor, self
        when :cursor_unexposed_attr
          attribute = Bro::parse_attribute(cursor)
          if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
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
      if enum_conf['type']
        @model.resolve_type_by_name(enum_conf['type'])
      else
        # If this is a named enum (objc_fixed_enum) we take the enum int type from the first value
        @enum_type.kind == :type_enum ? @model.resolve_type(@values.first.type.canonical) : @model.resolve_type(@enum_type)
      end
    end
    def enum_conf
      if !@enum_conf
        @enum_conf = @model.conf_enums[name] || (@model.conf_enums.find { |k, v| k == name || v['first'] == values.first.name } || [{}, {}])[1]
      end
      @enum_conf
    end
    def suffix
        enum_conf['suffix'] || ''
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
    attr_accessor :conf, :typedefs, :functions, :objc_classes, :objc_protocols, :objc_categories, :global_values, :global_value_enums, :global_value_dictionaries, :constant_values, :structs, :enums, :cfenums, 
      :cfoptions, :conf_functions, :conf_values, :conf_constants, :conf_classes, :conf_protocols, :conf_categories, :conf_enums
    def initialize(conf)
      @conf = conf
      @conf_typedefs = @conf['typedefs'] || {}
      @conf_enums = @conf['enums'] || {}
      @conf_functions = @conf['functions'] || {}
      @conf_values = conf['values'] || {}
      @conf_constants = conf['constants'] || {}
      @conf_classes = @conf['classes'] || {}
      @conf_protocols = @conf['protocols'] || {}
      @conf_categories = @conf['categories'] || {}
      @typedefs = []
      @functions = []
      @global_values = []
      @global_value_enums = Hash.new
      @global_value_dictionaries = Hash.new
      @constant_values = []
      @structs = []
      @objc_classes = []
      @objc_protocols = []
      @objc_categories = []
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
      orig_name = name
      name = @conf_typedefs[name] || name
      e = Bro::builtins_by_name(name)
      e = e || @enums.find {|e| e.name == name}
      e = e || @structs.find {|e| e.name == name}
      e = e || @objc_classes.find {|e| e.name == name}
      e = e || @objc_protocols.find {|e| e.name == name}
      e = e || @typedefs.find {|e| e.name == name}
      e = e || @global_value_enums[name]
      e = e || @global_value_dictionaries[name]
      e || (orig_name != name ? Builtin.new(name) : nil)
    end
    def resolve_type(type, allow_arrays = false, owner = nil, method = nil)
      t = @type_cache[type.spelling]
      if !t
        t = resolve_type0(type, allow_arrays, owner, method)
        raise "Failed to resolve type '#{type.spelling}' with kind #{type.kind} defined at #{Bro::location_to_s(type.declaration.location)}" unless t
        if t.is_a?(Typedef) && t.is_callback?
          # Callback.
          t = Bro::builtins_by_name("FunctionPtr")
        end
        if type.spelling != 'instancetype'
          @type_cache[type.spelling] = t
        end
      end
      t
    end
    def resolve_type0(type, allow_arrays = false, owner = nil, method = nil)
      if !type then return Bro::builtins_by_type_kind(:type_void) end
      name = type.spelling
      name = name.gsub(/\s*\bconst\b\s*/, '')
      name = name.sub(/^(struct|union|enum)\s*/, '')
      if @conf_typedefs[name]
        resolve_type_by_name name
      elsif type.kind == :type_pointer
        if type.pointee.kind == :type_unexposed && name.match(/\(\*\)/)
          # Callback. libclang does not expose info for callbacks.
          Bro::builtins_by_name('FunctionPtr')
        elsif type.pointee.kind == :type_typedef && type.pointee.declaration.typedef_type.kind == :type_function_proto
            Bro::builtins_by_name('FunctionPtr')
        else
          e = resolve_type(type.pointee)
          if e.is_a?(Enum) || e.is_a?(Typedef) && e.is_enum?
            # Pointer to enum. Use an appropriate integer pointer (e.g. IntPtr)
            enum = e.is_a?(Enum) ? e : e.enum
            if type.pointee.canonical.kind == :type_enum
              # Pointer to objc_fixed_enum
              enum.enum_type.pointer
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
        name = name.gsub(/\s*\bconst\b\s*/, '')
        if name =~ /^(id|NSObject)<(.*)>$/
          # Protocols
          names = $2.split(/\s*,/)
          types = names.map {|e| resolve_type_by_name(e)}
          if types.find_all {|e| !e}.empty?
            if types.size == 1
              types[0]
            else
              ObjCId.new(types)
            end
          else
            nil
          end
        elsif name =~ /^(Class)<(.*)>$/
          resolve_type_by_name('ObjCClass')
        else
          e = @objc_classes.find {|e| e.name == name}
          e && e.pointer
        end
      elsif type.kind == :type_enum
        @enums.find {|e| e.name == name}
      elsif type.kind == :type_incomplete_array || type.kind == :type_unexposed && name.end_with?('[]')
        # type is an unbounded array (void *[]). libclang does not expose info on such types.
        # Replace all [] with *
        name = name.gsub(/\[\]/, '*')
        name = name.sub(/^(id|NSObject)(<.*>)?\s*/, 'NSObject *')
        base = name.sub(/^([^\s*]+).*/, '\1')
        e = case base
        when /^(unsigned )?char$/ then resolve_type_by_name('byte')
        when /^long$/ then resolve_type_by_name('MachineSInt')
        when /^unsigned long$/ then resolve_type_by_name('MachineUInt')
        else resolve_type_by_name(base)
        end
        if e
          # Wrap in Pointer as many times as there are *s in name
          e = (1..name.scan(/\*/).count).inject(e) {|t, i| t.pointer}
        end
        e
      elsif type.kind == :type_unexposed
        e = @structs.find {|e| e.name == name}
        if !e
          if name.end_with?('[]')
            # type is an unbounded array (void *[]). libclang does not expose info on such types.
            # Replace all [] with *
            name = name.gsub(/\[\]/, '*')
            name = name.sub(/^(id|NSObject)(<.*>)?\s*/, 'NSObject *')
            base = name.sub(/^([^\s*]+).*/, '\1')
            e = case base
            when /^(unsigned )?char$/ then resolve_type_by_name('byte')
            when /^long$/ then resolve_type_by_name('MachineSInt')
            when /^unsigned long$/ then resolve_type_by_name('MachineUInt')
            else resolve_type_by_name(base)
            end
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
        if name == 'instancetype' && owner
          owner
        else
          td = @typedefs.find {|e| e.name == name}
          if !td
            # Check builtins for builtin typedefs like va_list
            Bro::builtins_by_name(name)
          else
            if td.is_callback? || td.is_struct? || td.is_enum?
              td
            elsif get_class_conf(td.name)
              td
            else
              e = @enums.find {|e| e.name == name}
              e || resolve_type(td.typedef_type)
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
        if allow_arrays
          Array.new(resolve_type(base_type), dimensions)
        else
          # Marshal as pointer
          (1..dimensions.size).inject(resolve_type(base_type)) {|t, i| t.pointer}
        end
      elsif type.kind == :type_block_pointer
        if name =~ /^void *\(\^\)\((void)?\)$/
          Block.new(Bro::builtins_by_type_kind(:type_void), [])
        elsif name =~ /^void *\(\^\)\(BOOL\)$/
          Block.new(Bro::builtins_by_type_kind(:type_void), [Bro::builtins_by_type_kind(:type_bool)])
        else
          $stderr.puts "WARN: Unknown block type #{name}. Using ObjCBlock."
          Bro::builtins_by_type_kind(type.kind)
        end
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

    def match_fully(pattern, s)
      pattern = pattern[1..-1] if pattern.start_with?('^')
      pattern = pattern.chop if pattern.end_with?('$')
      pattern = "^#{pattern}$"
      s.match(pattern)
    end

    def find_conf_matching(name, conf)
      match = conf.find {|pattern, value| $~ = match_fully(pattern.start_with?('+') ? "\\#{pattern}" : pattern, name)}
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
    def get_protocol_conf(name)
      get_conf_for_key(name, @conf_protocols)
    end
    def get_category_conf(name)
      get_conf_for_key(name, @conf_categories)
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
        "@Array({#{type.dimensions.join(', ')}}) #{type.java_name}"
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

    def getter_for_name(name, type, omit_prefix)
      base = omit_prefix ? name[0..-1] : name[0, 1].upcase + name[1..-1]
      getter = name
      if !omit_prefix
        if type == 'boolean'
          case name.to_s
            when /^is/, /^has/, /^can/, /^should/, /^adjusts/, /^allows/, /^always/, /^animates/, 
            /^applies/, /^apportions/, /^are/, /^autoenables/, /^automatically/, /^autoresizes/, 
            /^autoreverses/, /^bounces/, /^casts/, /^clears/, /^clips/, /^collapses/, /^contains/, 
            /^defers/, /^defines/, /^delays/, /^depends/, /^dims/, /^disconnects/, /^displays/, 
            /^does/, /^draws/, /^enables/, /^evicts/, /^expects/, /^fixes/, /^fills/, /^generates/, /^groups/, 
            /^hides/, /^ignores/, /^includes/, /^invalidates/, /^locks/, /^marks/, /^masks/, /^needs/,
            /^normalizes/, /^notifies/, /^pauses/, /^performs/, /^presents/, /^preserves/, /^propagates/,
            /^provides/, /^reads/, /^receives/, /^requests/, /^requires/, /^resets/, /^returns/, /^reverses/, 
            /^scrolls/, /^sends/, /^shows/, /^supports/, /^suppresses/, /^uses/, /^wants/, /^writes/   
              getter = name
            else
              getter = "is#{base}"
          end
        else
          getter = "get#{base}"
        end
      end
      getter
    end
    
    def setter_for_name(name, omit_prefix)
      base = omit_prefix ? name[0..-1] : name[0, 1].upcase + name[1..-1]
      omit_prefix ? base : "set#{base}"
    end
    
    def push_availability(entity, lines = [], indentation = "")
      since = entity.since
      deprecated = entity.deprecated
      if since || deprecated
        lines.push("#{indentation}/**")
        lines.push("#{indentation} * @since Available in iOS #{since} and later.") if since
        lines.push("#{indentation} * @deprecated Deprecated in iOS #{deprecated}.") if deprecated
        lines.push("#{indentation} */")
        lines.push("#{indentation}@Deprecated") if deprecated
      end
      lines
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
            src = src.sub(/^\((long long|long|int)\)/, '')
            # Only include macros that look like integer or floating point values for now
            if src =~ /^(([-+.0-9Ee]+[fF]?)|(~?0x[0-9a-fA-F]+[UL]*)|(~?[0-9]+[UL]*))$/i
              value = $1
              value = value.sub(/^((0x)?.*)U$/i, '\1')
              value = value.sub(/^((0x)?.*)UL$/i, '\1')
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
        when :cursor_obj_c_category_decl
          cat = ObjCCategory.new self, cursor
          c = get_category_conf("#{cat.name}@#{cat.owner}")
          c = get_category_conf(cat.name) unless c
          if c && c['protocol']
            @objc_protocols.push ObjCProtocol.new self, cursor
          else
            @objc_categories.push cat
          end
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

      # Filter out duplicate functions
      uniq_functions = @functions.uniq {|f| f.name}
      (@functions - uniq_functions).each do |f|
        definition = f.type.spelling.sub(/\(/, "#{f.name}(")
        $stderr.puts "WARN: Ignoring duplicate function '#{definition}' at #{Bro::location_to_s(f.location)}"
      end
      @functions = uniq_functions

      # Filter out global values not defined in the framework or library we're generating code for
      @global_values = @global_values.find_all {|v| is_included?(v)}
      # Remove duplicate global values (occurs in CoreData)
      @global_values = @global_values.uniq {|v| v.name}

	  # Create global value enumerations
	  @global_values.find_all {|v| v.enum}.each do |v|
	    if @global_value_enums[v.enum].nil?
	      @global_value_enums[v.enum] = GlobalValueEnumeration.new self, v.enum, v
	    else
	      @global_value_enums[v.enum].values.push v
	    end
	  end
      # Create global value dictionary wrappers
      @global_values.find_all {|v| v.dictionary}.each do |v|
        if @global_value_dictionaries[v.dictionary].nil?
          @global_value_dictionaries[v.dictionary] = GlobalValueDictionaryWrapper.new self, v.dictionary, @global_value_enums[v.enum], v
        else
          @global_value_dictionaries[v.dictionary].values.push v
        end
      end
      # Filter out global values that belong to an enumeration or dictionary wrapper
      @global_values = @global_values.find_all {|v| !v.enum && !v.dictionary}

      # Filter out constants not defined in the framework or library we're generating code for
      @constant_values = @constant_values.find_all {|v| is_included?(v)}
    end
  end
end

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
    value = value || ''
    template = template.gsub(/\/\*<#{key}>\*\/.*?\/\*<\/#{key}>\*\//m, "/*<#{key}>*/#{value}/*</#{key}>*/")
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
    member_name = (conf[e.name] || {})['name'] || e.name
    upcase_member_name = member_name.dup
    upcase_member_name[0] = upcase_member_name[0].capitalize
    type = (conf[e.name] || {})['type'] || model.to_java_type(model.resolve_type(e.type, true))
    getter = type == 'boolean' ? 'is' : 'get'
    members.push(["@StructMember(#{index}) public native #{type} #{getter}#{upcase_member_name}();", "@StructMember(#{index}) public native #{name} set#{upcase_member_name}(#{type} #{member_name});"].join("\n    "))
    index = index + inc
  end
  members = members.join("\n    ")
  data['members'] = "\n    #{members}\n    "

  constructor_params = []
  constructor_body = []
  struct.members.map do |e|
    member_name = (conf[e.name] || {})['name'] || e.name
    upcase_member_name = member_name.dup
    upcase_member_name[0] = upcase_member_name[0].capitalize
    
    type = (conf[e.name] || {})['type']
    type = type ? type.sub(/^(@ByVal|@Array.*)\s+/, '') : model.resolve_type(e.type, true).java_name
    constructor_params.push "#{type} #{member_name}"
    constructor_body.push "this.set#{upcase_member_name}(#{member_name});"
  end.join("\n    ")
  constructor = "public #{name}(" + constructor_params.join(', ') + ") {\n        "
  constructor = constructor + constructor_body.join("\n        ")
  constructor = "#{constructor}\n    }"
  data['constructors'] = "\n    public #{name}() {}\n    #{constructor}\n    "

  data['name'] = name
  data['visibility'] = conf['visibility'] || 'public'
  data['extends'] = "Struct<#{name}>"
  data['ptr'] = "public static class #{name}Ptr extends Ptr<#{name}, #{name}Ptr> {}"
  data['javadoc'] = "\n" + model.push_availability(struct).join("\n") + "\n"
  data
end

def opaque_to_java(model, data, name, conf)
  data = data || {}
  data['name'] = name
  data['visibility'] = conf['visibility'] || 'public'
  data['extends'] = conf['extends'] || 'NativeObject'
  data['ptr'] = "public static class #{name}Ptr extends Ptr<#{name}, #{name}Ptr> {}"
  data['constructors'] = "\n    protected #{name}() {}\n    "
  data
end

def is_init?(owner, method)
  owner.is_a?(Bro::ObjCClass) && method.is_a?(Bro::ObjCInstanceMethod) && 
      method.name.start_with?('init') && 
        (method.return_type.spelling == 'id' || 
         method.return_type.spelling == 'instancetype' ||
         method.return_type.spelling == "#{owner.name} *")
end

def get_generic_type(model, owner, method, type, index, conf_type, name = nil)
  if conf_type
    conf_type =~ /<\s*([A-Z0-9])+\s+>/ ? [$1, conf_type, name, nil] : [conf_type, nil, name, nil]
  else
    if is_init?(owner, method) && index == 0
      # init method return type should always be '@Pointer long'
      [Bro::builtins_by_name('Pointer').java_name, nil, name, nil]
    else
      resolved_type = model.resolve_type(type, false, owner, method)
      java_type = model.to_java_type(resolved_type)
      resolved_type.is_a?(Bro::ObjCId) && ["T#{index}", "T#{index} extends Object & #{java_type}", name, resolved_type] || [java_type, nil, name, resolved_type]
    end
  end
end

def property_to_java(model, owner, prop, props_conf, seen, adapter = false)
  return [] if prop.is_outdated?

  conf = model.get_conf_for_key(prop.name, props_conf) || {}
  
  if !conf['exclude']
    name = conf['name'] || prop.name
    
    type = get_generic_type(model, owner, prop, prop.type, 0, conf['type'])
    omit_prefix = conf['omit_prefix'] || false
    
    getter = ""
    if !conf['getter'].nil?
      getter = conf['getter']
    elsif
      getter = model.getter_for_name(name, type[0], omit_prefix)
    end
    setter = model.setter_for_name(name, omit_prefix)
    visibility = conf['visibility'] || 
        owner.is_a?(Bro::ObjCClass) && 'public' ||
        owner.is_a?(Bro::ObjCCategory) && 'public' ||
        adapter && 'public' || 
        owner.is_a?(Bro::ObjCProtocol) && model.get_protocol_conf(owner.name)['class'] && 'public' ||
        ''
    native = owner.is_a?(Bro::ObjCProtocol) && !model.get_protocol_conf(owner.name)['class'] ? "" : (adapter ? '' : "native")
    static = owner.is_a?(Bro::ObjCCategory) ? "static" : ""
    generics_s = [type].map {|e| e[1]}.find_all {|e| e}.join(', ')
    generics_s = generics_s.size > 0 ? "<#{generics_s}>" : ''
    param_types = []
    if owner.is_a?(Bro::ObjCCategory)
      param_types.unshift([owner.owner, nil, 'thiz'])
    end
    parameters_s = param_types.map {|p| "#{p[0]} #{p[2]}"}.join(', ')
    body = ';'
    if adapter
      body = " { throw new UnsupportedOperationException(); }"
    end
    lines = []
    if !seen["-#{prop.getter_name}"]
      model.push_availability(prop, lines)
      if adapter
        lines.push("@NotImplemented(\"#{prop.getter_name}\")")
      else
        lines.push("@Property(selector = \"#{prop.getter_name}\")")
      end
      lines.push("#{[visibility,static,native,generics_s,type[0],getter].find_all {|e| e.size>0}.join(' ')}(#{parameters_s})#{body}")
      seen["-#{prop.getter_name}"] = true
    end
    
    if !prop.is_readonly? && !conf['readonly'] && !seen["-#{prop.setter_name}"]
      param_types.push([type[0], nil, 'v'])
      parameters_s = param_types.map {|p| "#{p[0]} #{p[2]}"}.join(', ')
      model.push_availability(prop, lines)
      if adapter
        lines.push("@NotImplemented(\"#{prop.setter_name}\")")
      elsif (prop.attrs['assign'] || prop.attrs['weak'] || conf['strong']) && !conf['weak']
        # assign is used on some properties of primitives, structs and enums which isn't needed
        if type[0] =~ /^@(ByVal|MachineSized|Pointer)/ || type[0] =~ /\b(boolean|byte|short|char|int|long|float|double)$/ || type[3] && type[3].is_a?(Bro::Enum)
          lines.push("@Property(selector = \"#{prop.setter_name}\")")
        else
          lines.push("@Property(selector = \"#{prop.setter_name}\", strongRef = true)")
        end
      else
        lines.push("@Property(selector = \"#{prop.setter_name}\")")
      end
      lines.push("#{[visibility,static,native,generics_s,'void',setter].find_all {|e| e.size>0}.join(' ')}(#{parameters_s})#{body}")
      seen["-#{prop.setter_name}"] = true
    end
    lines
  else
    []
  end
end

def method_to_java(model, owner_name, owner, method, methods_conf, seen, adapter = false)
  return [[], []] if method.is_outdated?

  full_name = (method.is_a?(Bro::ObjCClassMethod) ? '+' : '-') + method.name
  conf = model.get_conf_for_key(full_name, methods_conf) || {}
  if seen[full_name]
    [[], []]
  elsif method.is_variadic? || !method.parameters.empty? && method.parameters[-1].type.spelling == 'va_list'
    param_types = method.parameters.map {|e| e.type.spelling}
    if (method.is_variadic?)
      param_types.push('...')
    end
    $stderr.puts "WARN: Ignoring variadic method '#{owner.name}.#{method.name}(#{param_types.join(', ')})' at #{Bro::location_to_s(method.location)}"
    [[], []]
  elsif !conf['exclude']
    ret_type = get_generic_type(model, owner, method, method.return_type, 0, conf['return_type'])
    params_conf = conf['parameters'] || {}
    param_types = method.parameters.inject([]) do |l, p|
      index = l.size + 1
      pconf = params_conf[p.name] || params_conf[l.size] || {}
      l.push(get_generic_type(model, owner, method, p.type, index, pconf['type'], pconf['name'] || p.name))
      l
    end
    name = conf['name']
    if !name
      name = method.name.gsub(/:/, '$')
      #name = name.sub(/\$$/, '')
      if method.parameters.empty? && method.return_type.kind != :type_void && conf['property']
        base = name[0, 1].upcase + name[1..-1]
        name = ret_type[0] == 'boolean' ? "is#{base}" : "get#{base}"
      elsif method.name.start_with?('set') && method.name.size > 3 && method.parameters.size == 1 && method.return_type.kind == :type_void # && conf['property']
        name = name.sub(/\$$/, '')
      elsif conf['trim_after_first_colon']
        name = name.sub(/\$.*/, '')
      end
    end
    # Default visibility is protected for init methods, public for other methods in classes and empty (public) for interface methods.
    visibility = conf['visibility'] || 
        owner.is_a?(Bro::ObjCClass) && (is_init?(owner, method) ? 'protected' : 'public') ||
        owner.is_a?(Bro::ObjCCategory) && 'public' || 
        adapter && 'public' || 
        owner.is_a?(Bro::ObjCProtocol) && model.get_protocol_conf(owner.name)['class'] && 'public' ||
        ''
    native = owner.is_a?(Bro::ObjCProtocol) && !model.get_protocol_conf(owner.name)['class'] || 
    	(owner.is_a?(Bro::ObjCCategory) && method.is_a?(Bro::ObjCClassMethod)) ? "" : (adapter ? '' : "native")
    static = method.is_a?(Bro::ObjCClassMethod) || owner.is_a?(Bro::ObjCCategory) ? "static" : ""
  #  lines = ["@Method", "#{visibility} #{static}#{native}#{java_type} #{name}();"]
    generics_s = ([ret_type] + param_types).map {|e| e[1]}.find_all {|e| e}.join(', ')
    generics_s = generics_s.size > 0 ? "<#{generics_s}>" : ''
    if owner.is_a?(Bro::ObjCCategory)
      if method.is_a?(Bro::ObjCInstanceMethod)
        param_types.unshift([owner.owner, nil, 'thiz'])
      end
    end
    parameters_s = param_types.map {|p| "#{p[0]} #{p[2]}"}.join(', ')
    
    ret_marshaler = conf['return_marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{conf['return_marshaler']})" : ''
    
    ret_anno = ''
    if generics_s.size > 0 && ret_type[0] =~ /^(@Pointer|@ByVal|@MachineSizedFloat|@MachineSizedSInt|@MachineSizedUInt)/
      # Generic types and an annotated return type. Move the annotation before the generic type info
      ret_anno = $1
      ret_type[0] = ret_type[0].sub(/^@.*\s+(.*)$/, '\1')
    end
    body = ';'
    if adapter
      body = " { throw new UnsupportedOperationException(); }"
    end
    method_lines = []
    constructor_lines = []
    model.push_availability(method, method_lines)
    if adapter
      method_lines.push("@NotImplemented(\"#{method.name}\")")
    else
      method_lines.push("@Method(selector = \"#{method.name}\")")
    end
    if owner.is_a?(Bro::ObjCCategory) && method.is_a?(Bro::ObjCClassMethod)
      new_parameters_s = (['ObjCClass clazz'] + (param_types.map {|p| "#{p[0]} #{p[2]}"})).join(', ')
      method_lines.push("protected static native #{[ret_marshaler,ret_anno,generics_s,ret_type[0],name].find_all {|e| e.size>0}.join(' ')}(#{new_parameters_s});")
      args_s = (["ObjCClass.getByType(#{owner.owner}.class)"] + (param_types.map {|p| p[2]})).join(', ')
      body = " { #{ret_type[0] != 'void' ? 'return ' : ''}#{name}(#{args_s}); }"
    end
    method_lines.push("#{[visibility,static,native,ret_marshaler,ret_anno,generics_s,ret_type[0],name].find_all {|e| e.size>0}.join(' ')}(#{parameters_s})#{body}")
    if owner.is_a?(Bro::ObjCClass) && is_init?(owner, method) && conf['constructor'] != false
      constructor_visibility = conf['constructor_visibility'] || 'public'
      args_s = param_types.map {|p| p[2]}.join(', ')
      model.push_availability(method, constructor_lines)
      constructor_lines.push("#{constructor_visibility}#{generics_s.size>0 ? ' ' + generics_s : ''} #{owner_name}(#{parameters_s}) { super((SkipInit) null); initObject(#{name}(#{args_s})); }")
    end
    seen[full_name] = true
    [method_lines, constructor_lines]
  else
    [[], []]
  end
end

@@mac_version = nil
@@ios_version = '8.1'
xcode_dir = `xcode-select -p`.chomp
sysroot = "#{xcode_dir}/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS#{@@ios_version}.sdk"

script_dir = File.expand_path(File.dirname(__FILE__))
target_dir = ARGV[0]
def_class_template = IO.read("#{script_dir}/class_template.java")
def_enum_template = IO.read("#{script_dir}/enum_template.java")
def_bits_template = IO.read("#{script_dir}/bits_template.java")
def_protocol_template = IO.read("#{script_dir}/protocol_template.java")
def_value_enum_template = IO.read("#{script_dir}/value_enum_template.java")
def_value_dictionary_template = IO.read("#{script_dir}/value_dictionary_template.java")
global = YAML.load_file("#{script_dir}/global.yaml")

ARGV[1..-1].each do |yaml_file|
  puts "Processing #{yaml_file}..."
  conf = YAML.load_file(yaml_file)

  headers = []
  headers.push(conf['header']) unless !conf['header']
  headers.concat(conf['headers']) unless !conf['headers']
  abort("Required 'header' or 'headers' value missing in #{yaml_file}") unless !headers.empty?

  conf = global.merge conf
  conf['typedefs'] = (global['typedefs'] || {}).merge(conf['typedefs'] || {}).merge(conf['private_typedefs'] || {})

  imports = []
  imports << "java.io.*"
  imports << "java.nio.*"
  imports << "java.util.*"
  imports << "org.robovm.objc.*"
  imports << "org.robovm.objc.annotation.*"
  imports << "org.robovm.objc.block.*"
  imports << "org.robovm.rt.*"
  imports << "org.robovm.rt.bro.*"
  imports << "org.robovm.rt.bro.annotation.*"
  imports << "org.robovm.rt.bro.ptr.*"
  imports = imports + (conf['imports'] || [])

  (conf['include'] || []).each do |f|
    f = Pathname.new(yaml_file).parent + f
    c = YAML.load_file(f)
    # Excluded all classes in included config
    c_classes = (c['classes'] || {}).inject({}) {|h, (k, v)| v = v || {}; v['exclude'] = true; h[k] = v; h}
    conf['classes'] = c_classes.merge(conf['classes'] || {})
    c_protocols = (c['protocols'] || {}).inject({}) {|h, (k, v)| v = v || {}; v['exclude'] = true; h[k] = v; h}
    conf['protocols'] = c_protocols.merge(conf['protocols'] || {})
    c_enums = (c['enums'] || {}).inject({}) {|h, (k, v)| v = v || {}; v['exclude'] = true; h[k] = v; h}
    conf['enums'] = c_enums.merge(conf['enums'] || {})
    conf['typedefs'] = (c['typedefs'] || {}).merge(conf['typedefs'] || {})
    conf['annotations'] = (c['annotations'] || []).concat(conf['annotations'] || [])
    if c['package']
      imports.push("#{c['package']}.*")
    end
  end

  imports.uniq!
  imports_s = "\n" + imports.map {|im| "import #{im};"}.join("\n") + "\n"

  index = FFI::Clang::Index.new
  clang_args = ['-arch', 'armv7', '-mthumb', '-miphoneos-version-min', '7.0', '-fblocks', '-isysroot', sysroot]
  headers[1 .. -1].each do |e|
    clang_args.push('-include')
    clang_args.push("#{sysroot}#{e}")
  end
  if conf['clang_args']
    clang_args = clang_args + conf['clang_args']
  end
  translation_unit = index.parse_translation_unit("#{sysroot}#{headers[0]}", clang_args, [], {:detailed_preprocessing_record=>true})

  model = Bro::Model.new conf
  model.process(translation_unit.cursor)

  package = conf['package'] || ''
  @@library = conf['library'] || ''
  default_class = conf['default_class'] || conf['framework'] || 'Functions'

  template_datas = {}

  potential_constant_enums = []
  model.enums.each do |enum|
    c = model.get_enum_conf(enum.name)
    if c && !c['exclude'] && !enum.is_outdated?
      data = {}
      java_name = enum.java_name
      bits = enum.is_options? || c['bits']
      ignore = c['ignore']
      if bits
        values = enum.values.find_all {|e| (!ignore || !e.name.match(ignore)) && !e.is_outdated?}.map do |e|
          model.push_availability(e).push("public static final #{java_name} #{e.java_name} = new #{java_name}(#{e.value}L)").join("\n    ")
        end.join(";\n    ") + ";"
        if !c['skip_none'] && !enum.values.find {|e| e.java_name == 'None'}
          values = "public static final #{java_name} None = new #{java_name}(0L);\n    #{values}"
        end
      else
        values = enum.values.find_all {|e| (!ignore || !e.name.match(ignore)) && !e.is_outdated?}.map do |e|
          model.push_availability(e).push("#{e.java_name}(#{e.value}L)").join("\n    ")
        end.join(",\n    ") + ";"
      end
      data['values'] = "\n    #{values}\n    "
      data['name'] = java_name
      if c['marshaler']
        data['annotations'] = (data['annotations'] || []).push("@Marshaler(#{c['marshaler']}.class)")
      else
        enum_type = enum.enum_type
        if enum_type.name =~ /^Machine(.)Int$/
          if !bits
            data['annotations'] = (data['annotations'] || []).push("@Marshaler(ValuedEnum.AsMachineSized#{$1}IntMarshaler.class)")
          else
            data['annotations'] = (data['annotations'] || []).push("@Marshaler(Bits.AsMachineSizedIntMarshaler.class)")
          end
        else
          typedefedas = model.typedefs.find {|e| e.name == java_name}
          if typedefedas
            if typedefedas.typedef_type.spelling == 'CFIndex'
              data['annotations'] = (data['annotations'] || []).push("@Marshaler(ValuedEnum.AsMachineSizedSIntMarshaler.class)")
            elsif typedefedas.typedef_type.spelling == 'CFOptionFlags'
              data['annotations'] = (data['annotations'] || []).push("@Marshaler(Bits.AsMachineSizedIntMarshaler.class)")
            end
          end
        end
      end
      data['imports'] = imports_s
      data['javadoc'] = "\n" + model.push_availability(enum).join("\n") + "\n"
      data['template'] = bits ? def_bits_template : def_enum_template
      template_datas[java_name] = data
#      merge_template(target_dir, package, java_name, bits ? def_bits_template : def_enum_template, data)
    elsif model.is_included?(enum) && (!c || !c['exclude'])
      # Possibly an enum with values that should be turned into constants
      potential_constant_enums.push(enum)
      $stderr.puts "WARN: Turning the enum #{enum.name} with first value #{enum.values[0].name} into constants"
    end
  end

  model.structs.find_all {|e| e.name.size > 0 }.each do |struct|
    c = model.get_class_conf(struct.name)
    if c && !c['exclude'] && !struct.is_outdated?
      name = c['name'] || struct.name
      template_datas[name] = struct.is_opaque? ? opaque_to_java(model, {}, name, c) : struct_to_java(model, {}, name, struct, c)
    end
  end
  model.typedefs.each do |td|
    c = model.get_class_conf(td.name)
    if c && !c['exclude']
      struct = td.struct
      if struct && struct.is_opaque?
        struct = model.structs.find {|e| e.name == td.struct.name} || td.struct
      end
      name = c['name'] || td.name
      template_datas[name] = (!struct || struct.is_opaque?) ? opaque_to_java(model, {}, name, c) : struct_to_java(model, {}, name, struct, c)
    end
  end

  # Assign global values to classes
  values = {}
  model.global_values.find_all {|v| v.is_available?(@@mac_version, @@ios_version) && !v.is_outdated?}.each do |v|
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
	
	last_static_class = nil
    vals.sort_by { |v, vconf| vconf['static_class'] }
    
    methods_s = vals.map do |(v, vconf)|
      lines = []
      name = vconf['name'] || v.name
      java_type = vconf['type'] || model.to_java_type(model.resolve_type(v.type, true))
      visibility = vconf['visibility'] || 'public'
      
	  # static class grouping support
      if last_static_class != vconf['static_class']
        if !last_static_class.nil?
          # End last static class.
          lines.push("}\n")
        end
      
        # Start new static class.
        last_static_class = vconf['static_class']
        
        lines.push("@Library(\"#{@@library}\")", "public static class #{last_static_class} {", "    static { Bro.bind(#{last_static_class}.class); }\n")
      end
      indentation = last_static_class.nil? ? "" : "    "
      
      
      model.push_availability(v, lines, indentation)
      if vconf.has_key?('dereference') && !vconf['dereference']
        lines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true, dereference=false)")
      else
        lines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)")
      end
      lines.push("#{indentation}#{visibility} static native #{java_type} #{name}();")
      if !v.is_const? && !vconf['readonly']
        model.push_availability(v, lines, indentation)
        lines = lines + ["#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)", "public static native void #{name}(#{java_type} v);"]
      end
      lines
    end.flatten.join("\n    ")
    
    if !last_static_class.nil?
      methods_s += "\n    }"
    end

    data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
    data['imports'] = imports_s
    data['annotations'] = (data['annotations'] || []).push("@Library(\"#{@@library}\")")
    data['bind'] = "static { Bro.bind(#{owner}.class); }"
    template_datas[owner] = data
  end
  
  def generate_global_value_enum_marshalers(lines, class_name, java_type)
    base_type = "NSObject"
    if java_type == "CFString"
      base_type = "CFType"
    end
  
    lines.push("public static class Marshaler {")
    lines.push("    @MarshalsPointer")
    lines.push("    public static #{class_name} toObject(Class<#{class_name}> cls, long handle, long flags) {")
    lines.push("        #{java_type} o = (#{java_type}) #{base_type}.Marshaler.toObject(#{java_type}.class, handle, flags);")
    lines.push("        if (o == null) {")
    lines.push("            return null;")
    lines.push("        }")
    lines.push("        return #{class_name}.valueOf(o);")
    lines.push("    }")
    lines.push("    @MarshalsPointer")
    lines.push("    public static long toNative(#{class_name} o, long flags) {")
    lines.push("        if (o == null) {")
    lines.push("            return 0L;")
    lines.push("        }")
    lines.push("        return #{base_type}.Marshaler.toNative(o.value(), flags);")
	lines.push("    }")
    lines.push("}")
    
    lines.push("public static class AsListMarshaler {")
    lines.push("    @SuppressWarnings(\"unchecked\")") if base_type == "NSObject"
    lines.push("    @MarshalsPointer")
    lines.push("    public static List<#{class_name}> toObject(Class<? extends #{base_type}> cls, long handle, long flags) {")
    if base_type == "NSObject"
      lines.push("        NSArray<#{java_type}> o = (NSArray<#{java_type}>) NSObject.Marshaler.toObject(cls, handle, flags);")
    else 
      lines.push("        CFArray o = (CFArray) CFType.Marshaler.toObject(cls, handle, flags);")
    end
    lines.push("        if (o == null) {")
    lines.push("            return null;")
    lines.push("        }")
    lines.push("        List<#{class_name}> list = new ArrayList<>();")
    lines.push("        for (long i = 0, n = o.size(); i < n; i++) {")
    if base_type == "NSObject"
      lines.push("            list.add(#{class_name}.valueOf(o.get(i)));")
    else
      lines.push("            list.add(#{class_name}.valueOf(o.get(i, #{java_type}.class)));")
    end
    lines.push("        }")
    lines.push("        return list;")
    lines.push("    }")
    lines.push("    @MarshalsPointer")
    lines.push("    public static long toNative(List<#{class_name}> l, long flags) {")
    lines.push("        if (l == null) {")
    lines.push("            return 0L;")
    lines.push("        }")
    if base_type == "NSObject"
      lines.push("        NSArray<#{java_type}> array = new NSMutableArray<>();")
    else
      lines.push("        CFArray array = CFMutableArray.create();")
    end
    lines.push("        for (#{class_name} i : l) {")
    lines.push("            array.add(i.value());")
	lines.push("        }")
    lines.push("        return #{base_type}.Marshaler.toNative(array, flags);")
	lines.push("    }")
    lines.push("}")
    
    lines
  end
  
  # Generate template data for global value enumerations
  model.global_value_enums.each do |name, e|
    data = template_datas[name] || {}
    data['name'] = name
    data['type'] = e.java_type
    
	marshaler_lines = []
	generate_global_value_enum_marshalers(marshaler_lines, name, e.java_type)
    
    marshalers_s = marshaler_lines.flatten.join("\n    ")
    
    names = []
    vlines = []
    clines = []
    indentation = "    "
    
    e.values.sort_by { |v| v.since }
    
    e.values.find_all {|v| v.is_available?(@@mac_version, @@ios_version) && !v.is_outdated?}.each do |v|
      vconf = model.get_value_conf(v.name)
      
      vname = vconf['name'] || v.name
      vname = "_#{vname}" if vname.match(/^[0-9]/)
      
      names.push(vname)
      java_type = vconf['type'] || model.to_java_type(model.resolve_type(v.type, true))
      visibility = vconf['visibility'] || 'public'
            
      model.push_availability(v, vlines, indentation)
      if vconf.has_key?('dereference') && !vconf['dereference']
        vlines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true, dereference=false)")
      else
        vlines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)")
      end
      vlines.push("#{indentation}#{visibility} static native #{java_type} #{vname}();")
      
      model.push_availability(v, clines)
      clines.push("public static final #{name} #{vname} = new #{name}(\"#{vname}\");")
      
    end
    
    values_s = vlines.flatten.join("\n    ")
    constants_s = clines.flatten.join("\n    ")
    value_list_s = names.flatten.join(", ")
    
    data['marshalers'] = "\n    #{marshalers_s}\n    "
    data['values'] = "\n    #{values_s}\n        "
    data['constants'] = "\n    #{constants_s}\n    "
    data['extends'] = "GlobalValueEnumeration<#{e.java_type}>"
    data['imports'] = imports_s
    data['value_list'] = value_list_s
    data['annotations'] = (data['annotations'] || []).push("@Library(\"#{@@library}\")")
    data['template'] = def_value_enum_template
    template_datas[name] = data
  end

  # Generate template data for global value dictionary wrappers
  model.global_value_dictionaries.each do |name, d|
    data = template_datas[name] || {}
    d.generate_template_data(data)
    
    data['imports'] = imports_s
    data['template'] = def_value_dictionary_template
    
    template_datas[name] = data
  end

  # Assign functions to classes
  functions = {}
  model.functions.find_all {|f| f.is_available?(@@mac_version, @@ios_version) && !f.is_outdated?}.each do |f|
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
      lines = []
	  model.push_availability(f, lines)
	  visibility = fconf['visibility'] || 'public'
	  parameters = f.parameters
      static = "static "
  	  paramconf = fconf['parameters'] || {}
	  firstparamconf = parameters.size >= 1 ? paramconf[parameters[0].name] : nil
	  firstparamtype = (firstparamconf || {})['type']
	  if !fconf['static'] && parameters.size >= 1 && (firstparamtype == owner || model.resolve_type(parameters[0].type).java_name == owner)
	  	# Instance method
		java_type = model.to_java_type(model.resolve_type(parameters[0].type))
		if !firstparamtype && java_type.include?('@ByVal')
		  # If the instance is passed @ByVal we need to make a wrapper method and keep the @Bridge method static
		  java_ret = fconf['return_type'] || model.resolve_type(f.return_type).java_name
		  java_parameters = parameters[1..-1].map do |e|
		  	pconf = paramconf[e.name] || {}
		  	marshaler = pconf['marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{pconf['marshaler']}.class) " : ''
		    "#{marshaler}#{pconf['type'] || model.resolve_type(e.type).java_name} #{pconf['name'] || e.name}"
		  end
		  args = parameters[1..-1].map do |e|
		 	pconf = paramconf[e.name] || {}
			pconf['name'] || e.name
		  end
		  args.unshift('this')
		  lines.push("#{visibility} #{java_ret} #{name}(#{java_parameters.join(', ')}) { #{java_ret != 'void' ? 'return ' : ''}#{name}(#{args.join(', ')}); }")
		  # Alter the visibility for the @Bridge method to private
		  visibility = 'private'
		else
		  parameters = parameters[1..-1]
		  static = ""
		end
	  end
	  
	  java_ret_marshaler = fconf['return_marshaler']
      if java_ret_marshaler
        java_ret_marshaler = "@org.robovm.rt.bro.annotation.Marshaler(#{java_ret_marshaler}.class) "
      else
        java_ret_marshaler = ""
      end
	  
	  java_ret = fconf['return_type'] || model.to_java_type(model.resolve_type(f.return_type))
	  java_parameters = parameters.map do |e|
	    pconf = paramconf[e.name] || {}
	    marshaler = pconf['marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{pconf['marshaler']}.class) " : ''
		"#{marshaler}#{pconf['type'] || model.to_java_type(model.resolve_type(e.type))} #{pconf['name'] || e.name}"
	  end
	  lines.push("@Bridge(symbol=\"#{f.name}\", optional=true)")
	  lines.push("#{visibility} #{static}native #{java_ret_marshaler}#{java_ret} #{name}(#{java_parameters.join(', ')});")
      lines
    end.flatten.join("\n    ")
    data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
    data['imports'] = imports_s
    data['annotations'] = (data['annotations'] || []).push("@Library(\"#{@@library}\")")
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
    type = enum.enum_type.java_name.match(/\blong$/) ? 'long' : 'int'
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
      visibility = vconf['visibility'] || 'public'
      java_type = vconf['type'] || v.type || 'double'
      ["#{visibility} static final #{java_type} #{name} = #{v.value};"]
    end.flatten.join("\n    ")
    data['constants'] = (data['constants'] || '') + "\n    #{constants_s}\n    "
    data['imports'] = imports_s
    template_datas[owner] = data
  end


  # Assign methods and properties to classes/protocols
  members = {}
  (model.objc_classes + model.objc_protocols).each do |cls|
    c = cls.is_a?(Bro::ObjCClass) ? model.get_class_conf(cls.name) : model.get_protocol_conf(cls.name)
    if c && !c['exclude']
      owner = c['name'] || cls.java_name
      members[owner] = members[owner] || {owner: cls, owner_name: owner, members: [], conf: c}
      members[owner][:members].push([cls.instance_methods + cls.class_methods + cls.properties, c])
    end
  end
  unassigned_categories = []
  model.objc_categories.each do |cat|
    c = model.get_category_conf("#{cat.name}@#{cat.owner}")
    c = model.get_category_conf(cat.name) unless c
    owner_name = c && c['owner'] || cat.owner
    owner_cls = model.objc_classes.find {|e| e.name == owner_name}
    owner = nil
    if owner_cls
      owner_conf = model.get_class_conf(owner_cls.name)
      if owner_conf && !owner_conf['exclude']
        owner = owner_conf['name'] || owner_cls.java_name
        members[owner] = members[owner] || {owner: owner_cls, owner_name: owner, members: [], conf: owner_conf}
        members[owner][:members].push([cat.instance_methods + cat.class_methods + cat.properties, owner_conf])
        owner_cls.protocols = owner_cls.protocols + cat.protocols
      end
    end
    if !owner && model.is_included?(cat)
      unassigned_categories.push(cat)
    end
  end
  unassigned_categories.each do |cat|
    c = model.get_category_conf("#{cat.name}@#{cat.owner}")
    c = model.get_category_conf(cat.name) unless c
    c = model.get_category_conf(cat.owner) unless c
    if c && !c['exclude']
      owner = c['name'] || cat.java_name
      members[owner] = members[owner] || {owner: cat, owner_name: owner, members: [], conf: c}
      members[owner][:members].push([cat.instance_methods + cat.class_methods + cat.properties, c])
    else
      $stderr.puts "WARN: Skipping category #{cat.name} for #{cat.owner}"
    end
  end

  def all_protocols(model, cls, conf)
    def f(model, cls, conf)
      result = []
      if (conf == nil)
        return result
      end
      (conf['protocols'] || cls.protocols).each do |prot_name|
        prot = model.objc_protocols.find {|p| p.name == prot_name}
        protc = model.get_protocol_conf(prot.name) unless !prot
        if protc # && !protc['exclude']
          result.push([prot, protc])
          result = result + f(model, prot, protc)
        end
      end
      result
    end
    def g(model, cls, conf)
      r = []
      if !cls.is_a?(Bro::ObjCProtocol) && cls.superclass
        supercls = model.objc_classes.find {|e| e.name == cls.superclass}
        super_conf = model.get_class_conf(supercls.name)
        r = g(model, supercls, super_conf)
      end
      r + f(model, cls, conf)
    end
    g(model, cls, conf).uniq {|e| e[0].name}
  end

  # Add all methods defined by protocols to all implementing classes
  model.objc_classes.find_all {|cls| !cls.is_opaque?}.each do |cls|
    c = model.get_class_conf(cls.name)
    if c && !c['exclude']
      owner = c['name'] || cls.java_name
      prots = all_protocols(model, cls, c)
      if cls.superclass
        prots = prots - all_protocols(model, model.objc_classes.find {|e| e.name == cls.superclass} , model.get_class_conf(cls.superclass))
      end
      prots.each do |(prot, protc)|
        members[owner] = members[owner] || {owner: cls, owner_name: owner, members: [], conf: c}
        members[owner][:members].push([prot.instance_methods + prot.class_methods + prot.properties, protc])
      end
    end
  end
  
  # Add all methods defined by protocols to all implementing converted protocol classes
  model.objc_protocols.find_all do |cls|
    c = model.get_protocol_conf(cls.name)
    if c && !c['exclude'] && c['class']
      owner = c['name'] || cls.java_name
      prots = all_protocols(model, cls, c)
      prots.each do |(prot, protc)|
        members[owner] = members[owner] || {owner: cls, owner_name: owner, members: [], conf: c}
        members[owner][:members].push([prot.instance_methods + prot.class_methods + prot.properties, protc])
      end
    end
  end

  def protocol_list(model, protocols, conf)
    l = []
    if conf['protocols']
      l = conf['protocols']
    else
      protocols.each do |name|
        c = model.get_protocol_conf(name)
        if c
          l.push(model.objc_protocols.find {|p| p.name == name}.java_name)
        end
      end
    end
    l
  end

  def protocol_list_s(model, keyword, protocols, conf)
    l = protocol_list(model, protocols, conf)
    l.empty? ? nil : (keyword + " " + l.join(', '))
  end

  model.objc_classes.find_all {|cls| !cls.is_opaque?} .each do |cls|
    c = model.get_class_conf(cls.name)
    if c && !c['exclude'] && !cls.is_outdated?
      name = c['name'] || cls.java_name
      data = template_datas[name] || {}
      data['name'] = name
      data['visibility'] = c['visibility'] || 'public'
      data['extends'] = c['extends'] || (cls.superclass && (model.conf_classes[cls.superclass] || {})['name'] || cls.superclass) || 'ObjCObject'
      data['imports'] = imports_s
      data['implements'] = protocol_list_s(model, 'implements', cls.protocols, c)
      data['ptr'] = "public static class #{cls.java_name}Ptr extends Ptr<#{cls.java_name}, #{cls.java_name}Ptr> {}"
      data['annotations'] = (data['annotations'] || []).push("@Library(\"#{@@library}\")").push("@NativeClass")
      data['bind'] = "static { ObjCRuntime.bind(#{name}.class); }"
      data['javadoc'] = "\n" + model.push_availability(cls).join("\n") + "\n"
      template_datas[name] = data
    end
  end

  model.objc_protocols.each do |prot|
    c = model.get_protocol_conf(prot.name)
    if c && !c['exclude'] && !prot.is_outdated?
      name = c['name'] || prot.java_name
      data = template_datas[name] || {}
      data['name'] = name
      data['visibility'] = c['visibility'] || 'public'
      if c['class']
        data['extends'] = c['extends'] || 'NSObject'
        data['implements'] = protocol_list_s(model, 'implements', prot.protocols, c)
        data['ptr'] = "public static class #{prot.java_name}Ptr extends Ptr<#{prot.java_name}, #{prot.java_name}Ptr> {}"
        data['annotations'] = (data['annotations'] || []).push("@Library(\"#{@@library}\")")
        data['bind'] = "static { ObjCRuntime.bind(#{name}.class); }"
      else
        data['implements'] = protocol_list_s(model, 'extends', prot.protocols, c) || 'extends NSObjectProtocol'
        data['template'] = def_protocol_template
      end
      data['imports'] = imports_s
      data['javadoc'] = "\n" + model.push_availability(prot).join("\n") + "\n"
      template_datas[name] = data
    end
  end

  # Add methods/properties to protocol interface adapter classes
  members.values.each do |h|
    owner = h[:owner]
    if owner.is_a?(Bro::ObjCProtocol)
      c = model.get_protocol_conf(owner.name)
      if !c['skip_adapter'] && !c['class']
        interface_name = c['name'] || owner.java_name
        owner_name = (interface_name) + 'Adapter'
        methods_lines = []
        properties_lines = []
        h[:members].each do |(members, c)|
          members.find_all {|m| m.is_a?(Bro::ObjCMethod)}.each do |m|
            a = method_to_java(model, owner_name, owner, m, c['methods'] || {}, {}, true)
            methods_lines.concat(a[0])
          end
          members.find_all {|m| m.is_a?(Bro::ObjCProperty)}.each do |p|
            properties_lines.concat(property_to_java(model, owner, p, c['properties'] || {}, {}, true))
          end
        end

        data = template_datas[owner_name] || {}
        data['name'] = owner_name
        protocols = protocol_list(model, owner.protocols, c).find_all {|e| e != 'NSObjectProtocol'}
        data['extends'] = protocols.empty? ? 'NSObject' : "#{protocols[0]}Adapter"
        data['implements'] = "implements #{interface_name}"
        methods_s = methods_lines.flatten.join("\n    ")
        data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
        properties_s = properties_lines.flatten.join("\n    ")
        data['properties'] = (data['properties'] || '') + "\n    #{properties_s}\n    "
        template_datas[owner_name] = data
      end
    end
  end

  members.values.each do |h|
    owner = h[:owner]
    c = h[:conf]
    owner_name = h[:owner_name]
    seen = {}
    methods_lines = []
    constructors_lines = []
    properties_lines = []
    h[:members].each do |(members, c)|
      members.find_all {|m| m.is_a?(Bro::ObjCMethod) && m.is_available?(@@mac_version, @@ios_version)}.each do |m|
        a = method_to_java(model, owner_name, owner, m, c['methods'] || {}, seen)
        methods_lines.concat(a[0])
        constructors_lines.concat(a[1])
      end
      members.find_all {|m| m.is_a?(Bro::ObjCProperty) && m.is_available?(@@mac_version, @@ios_version)}.each do |p|
        properties_lines.concat(property_to_java(model, owner, p, c['properties'] || {}, seen))
      end
    end

    data = template_datas[owner_name] || {}
    data['name'] = owner_name
    if owner.is_a?(Bro::ObjCClass)
      if !c['skip_skip_init_constructor']
        constructors_lines.unshift("protected #{owner_name}(SkipInit skipInit) { super(skipInit); }")
      end
      if !c['skip_def_constructor']
        constructors_lines.unshift("public #{owner_name}() {}")
      end
    elsif owner.is_a?(Bro::ObjCCategory)
      constructors_lines.unshift("private #{owner_name}() {}")
      data['annotations'] = (data['annotations'] || []).push("@Library(\"#{@@library}\")")
      data['bind'] = "static { ObjCRuntime.bind(#{owner_name}.class); }"
      data['visibility'] = c['visibility'] || 'public final'
      data['extends'] = 'NSExtensions'
    end
    methods_s = methods_lines.flatten.join("\n    ")
    constructors_s = constructors_lines.flatten.join("\n    ")
    properties_s = properties_lines.flatten.join("\n    ")
    data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
    data['constructors'] = (data['constructors'] || '') + "\n    #{constructors_s}\n    "
    data['properties'] = (data['properties'] || '') + "\n    #{properties_s}\n    "
    template_datas[owner_name] = data
  end

  template_datas.each do |owner, data|
    c = model.get_class_conf(owner) || model.get_protocol_conf(owner) || model.get_category_conf(owner) || model.get_enum_conf(owner) || {}
    data['imports'] = imports_s
    data['visibility'] = data['visibility'] || c['visibility'] || 'public'
    data['extends'] = data['extends'] || c['extends'] || 'CocoaUtility'
    
    data['annotations'] = (data['annotations'] || []).concat(c['annotations'] || []).concat(conf['annotations'] || [])
    data['annotations'] = data['annotations'] && !data['annotations'].empty? ? data['annotations'].uniq.join(' ') : nil
    data['implements'] = data['implements'] || nil
    data['properties'] = data['properties'] || nil
    data['constructors'] = data['constructors'] || nil
    data['members'] = data['members'] || nil
    data['methods'] = data['methods'] || nil
    data['constants'] = data['constants'] || nil
    if c['add_ptr']
      data['ptr'] = "public static class #{owner}Ptr extends Ptr<#{owner}, #{owner}Ptr> {}"
    end
    merge_template(target_dir, package, owner, data['template'] || def_class_template, data)
  end

end
