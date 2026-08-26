#!/usr/bin/env ruby
# frozen_string_literal: true

# Ruby -> JSON structural bridge (stdlib Ripper, no gems). One file per invocation:
#   ruby ruby_graph.rb <file.rb>
# Emits symbols (classes/modules with superclass extends and include implements,
# defs as methods with their enclosing class as container, visibility tracked
# through bare private/protected/public markers), require/require_relative import
# specs, and call sites (Const.new maps to the class name so instantiation counts
# as class usage). The taint bridge ruby_ast.rb is untouched.
require "json"
require "ripper"

src = File.read(ARGV[0])
sexp = Ripper.sexp(src)
if sexp.nil?
  STDERR.write("PARSE_ERROR")
  exit 2
end

SYMBOLS = []
CALLS = []
IMPORTS = []

VISIBILITY = %w[private protected public].freeze

def pos?(node)
  node.is_a?(Array) && node.length == 2 && node[0].is_a?(Integer) && node[1].is_a?(Integer)
end

def first_line(node)
  return nil unless node.is_a?(Array)
  return node[0] if pos?(node)
  node.each do |c|
    l = first_line(c)
    return l if l
  end
  nil
end

def max_line(node)
  return 0 unless node.is_a?(Array)
  return node[0] if pos?(node)
  node.map { |c| max_line(c) }.max || 0
end

def const_name(node)
  return nil unless node.is_a?(Array)
  case node[0]
  when :const_ref, :var_ref then const_name(node[1])
  when :top_const_ref
    name = const_name(node[1])
    name ? "::#{name}" : nil
  when :const_path_ref, :const_path_field
    left = const_name(node[1])
    right = const_name(node[2])
    left && right ? "#{left}::#{right}" : (right || left)
  when :@const then node[1]
  end
end

def scoped_const(name, container)
  return name unless name && container && !name.include?("::")
  "#{container}::#{name}"
end

def receiver_name(node)
  return nil unless node.is_a?(Array)
  name = const_name(node)
  return name if name
  case node[0]
  when :var_ref
    tok = node[1]
    tok[1] if tok.is_a?(Array) && %i[@ident @kw @const].include?(tok[0])
  when :@ident, :@kw, :@const
    node[1]
  end
end

def string_lit(node)
  out = nil
  stack = [node]
  until stack.empty?
    n = stack.pop
    next unless n.is_a?(Array)
    if n[0] == :@tstring_content
      out = (out || "") + n[1]
    else
      n.each { |c| stack << c if c.is_a?(Array) }
    end
  end
  out
end

def param_names(params_node)
  node = params_node
  node = node[1] if node.is_a?(Array) && node[0] == :paren
  return [] unless node.is_a?(Array) && node[0] == :params
  (node[1] || []).map { |p| p.is_a?(Array) && p[0] == :@ident ? p[1] : nil }.compact
end

def body_is_stub(bodystmt)
  return false unless bodystmt.is_a?(Array) && bodystmt[0] == :bodystmt
  stmts = (bodystmt[1] || []).reject { |s| s.is_a?(Array) && s[0] == :void_stmt }
  return true if stmts.empty?
  return false unless stmts.length == 1
  s = stmts[0]
  return false unless s.is_a?(Array)
  callee = s[1]
  if (s[0] == :command || s[0] == :fcall) && callee.is_a?(Array) &&
     callee[0] == :@ident && callee[1] == "raise"
    return JSON.generate(s).include?("NotImplementedError")
  end
  false
end

def emit_def(name_node, params_node, bodystmt, container, exported)
  return unless name_node.is_a?(Array) && (name_node[0] == :@ident || name_node[0] == :@const)
  name = name_node[1]
  line = name_node[2][0]
  SYMBOLS << {
    "name" => name, "kind" => container ? "method" : "function",
    "container" => container, "start" => line,
    "end" => [max_line(bodystmt), line].max,
    "exported" => exported, "stub" => body_is_stub(bodystmt),
    "params" => param_names(params_node), "extends" => [], "implements" => []
  }
end

def handle_command(node, sym)
  callee = node[1]
  return unless callee.is_a?(Array) && callee[0] == :@ident
  name = callee[1]
  line = callee[2][0]
  case name
  when "require_relative", "require"
    path = string_lit(node[2])
    IMPORTS << { "path" => path, "line" => line, "kind" => name } if path
  when "include", "extend", "prepend"
    mod = const_name(node[2].is_a?(Array) ? node[2] : nil) || begin
      found = nil
      stack = [node[2]]
      until stack.empty?
        n = stack.pop
        next unless n.is_a?(Array)
        if n[0] == :@const
          found = n[1]
          break
        end
        n.each { |c| stack << c if c.is_a?(Array) }
      end
      found
    end
    sym["implements"] << mod if sym && mod && !sym["implements"].include?(mod)
  else
    CALLS << { "from_line" => line, "name" => name, "receiver" => nil }
  end
end

def walk(node, container, priv)
  return unless node.is_a?(Array)
  case node[0]
  when :class
    name = scoped_const(const_name(node[1]), container)
    ext = node[2] ? [const_name(node[2])].compact : []
    sym = { "name" => name, "kind" => "class",
            "start" => first_line(node[1]) || 0, "end" => max_line(node),
            "exported" => true, "stub" => false, "params" => [],
            "extends" => ext, "implements" => [] }
    SYMBOLS << sym
    walk_body(node[3], sym)
  when :module
    name = scoped_const(const_name(node[1]), container)
    sym = { "name" => name, "kind" => "class",
            "start" => first_line(node[1]) || 0, "end" => max_line(node),
            "exported" => true, "stub" => false, "params" => [],
            "extends" => [], "implements" => [] }
    SYMBOLS << sym
    walk_body(node[2], sym)
  when :def
    emit_def(node[1], node[2], node[3], container, !priv[0])
    walk(node[3], container, priv)
  when :defs
    emit_def(node[3], node[4], node[5], container, !priv[0])
    walk(node[5], container, priv)
  when :vcall
    id = node[1]
    if id.is_a?(Array) && id[0] == :@ident && !VISIBILITY.include?(id[1])
      CALLS << { "from_line" => id[2][0], "name" => id[1], "receiver" => nil }
    end
  when :fcall
    id = node[1]
    CALLS << { "from_line" => id[2][0], "name" => id[1], "receiver" => nil } if id.is_a?(Array) && id[0] == :@ident
  when :command
    handle_command(node, nil)
    node[2..].each { |c| walk(c, container, priv) } if node.length > 2
  when :call
    meth = node[3]
    if meth.is_a?(Array) && meth[0] == :@ident
      if meth[1] == "new" && (recv = const_name(node[1]))
        CALLS << { "from_line" => meth[2][0], "name" => recv, "receiver" => recv }
      else
        CALLS << { "from_line" => meth[2][0], "name" => meth[1],
                   "receiver" => receiver_name(node[1]) }
      end
    end
    walk(node[1], container, priv)
  when :command_call
    meth = node[3]
    if meth.is_a?(Array) && meth[0] == :@ident
      CALLS << { "from_line" => meth[2][0], "name" => meth[1],
                 "receiver" => receiver_name(node[1]) }
    end
    walk(node[1], container, priv)
    walk(node[4], container, priv)
  else
    node.each { |c| walk(c, container, priv) if c.is_a?(Array) }
  end
end

def walk_body(bodystmt, sym)
  return unless bodystmt.is_a?(Array)
  priv = [false]
  stmts = bodystmt[0] == :bodystmt ? (bodystmt[1] || []) : bodystmt
  stmts.each do |stmt|
    next unless stmt.is_a?(Array)
    if stmt[0] == :vcall && stmt[1].is_a?(Array) && stmt[1][0] == :@ident &&
       VISIBILITY.include?(stmt[1][1])
      priv[0] = stmt[1][1] != "public"
    elsif stmt[0] == :command
      handle_command(stmt, sym)
      stmt[2..].each { |c| walk(c, sym["name"], priv) } if stmt.length > 2
    else
      walk(stmt, sym["name"], priv)
    end
  end
end

walk(sexp, nil, [false])
puts JSON.generate({ "symbols" => SYMBOLS, "calls" => CALLS, "imports" => IMPORTS })
