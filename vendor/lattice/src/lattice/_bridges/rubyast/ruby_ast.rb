# Ruby -> JSON bridge for the command-injection ingest. Walks the native Ripper sexp IN RUBY and emits
# per-function {name, assigns:[{lhs,rhs}], calls:[{callee,args}]} — the analog of the Go/Rust bridges.
require 'ripper'; require 'json'

def collect_names(node, out)
  return unless node.is_a?(Array)
  if node[0] == :@ident && node[1].is_a?(String) then out << node[1]; return end
  if node[0] == :@const && node[1].is_a?(String) then out << node[1]; return end  # ENV/ARGV (constants)
  node.each { |c| collect_names(c, out) }
end

def param_names(pnode)
  # Ordered positional parameter names of a def's param list (required + optionals), for interprocedural
  # sink-parameter matching. Ripper: [:params, required, optionals, rest, post, kw, kwrest, block].
  out = []
  return out unless pnode.is_a?(Array)
  p = pnode[0] == :paren ? pnode[1] : pnode
  return out unless p.is_a?(Array) && p[0] == :params
  (p[1] || []).each { |r| out << r[1] if r.is_a?(Array) && r[0] == :@ident }            # required
  (p[2] || []).each { |o| out << o[0][1] if o.is_a?(Array) && o[0].is_a?(Array) && o[0][0] == :@ident }  # optional
  out
end

def collect_returns(node, out, f)
  # explicit `return X` expressions anywhere in this scope (not descending into nested scopes)
  return unless node.is_a?(Array)
  if node[0] == :return || node[0] == :return0
    n = []; collect_names(node, n); collect_call_identities(node, n, f); out << n.uniq
  end
  node.each { |c| collect_returns(c, out, f) if c.is_a?(Array) && ![:def, :defs, :class, :module].include?(c[0]) }
end

def return_names(body, f)
  # name footprints of this method's RETURN values: every explicit `return X`, PLUS Ruby's implicit return
  # (the value of the LAST statement in the body) — needed for the return-taint summary.
  out = []
  collect_returns(body, out, f)
  if body.is_a?(Array) && body[0] == :bodystmt && body[1].is_a?(Array) && !body[1].empty?
    n = []; collect_names(body[1][-1], n); collect_call_identities(body[1][-1], n, f); out << n.uniq
  end
  out
end

def method_name(callee)
  return nil unless callee.is_a?(Array)
  case callee[0]
  when :fcall, :vcall
    callee[1].is_a?(Array) && callee[1][0] == :@ident ? callee[1][1] : nil
  when :call, :command_call
    m = callee[3] || callee[1]
    m.is_a?(Array) && m[0] == :@ident ? m[1] : nil
  when :@ident
    callee[1]
  end
end

def constant_path(node)
  return nil unless node.is_a?(Array)
  case node[0]
  when :@const
    node[1]
  when :var_ref, :const_ref, :top_const_ref
    constant_path(node[1])
  when :const_path_ref, :const_path_field
    left = constant_path(node[1]); right = constant_path(node[2])
    left && right ? "#{left}::#{right}" : (right || left)
  when :call
    # `Clean.new` proves the receiver class of the following instance-method call.
    method_name(node) == 'new' ? constant_path(node[1]) : nil
  end
end

def self_receiver?(node)
  node.is_a?(Array) && node[0] == :var_ref && node[1].is_a?(Array) &&
    node[1][0] == :@kw && node[1][1] == 'self'
end

def qualified_method_name(callee, f)
  name = method_name(callee)
  return nil unless name
  return name unless callee.is_a?(Array) && [:call, :command_call].include?(callee[0])
  recv = callee[1]
  if recv.is_a?(Array) && recv[0] == :call && method_name(recv) == 'new'
    klass = constant_path(recv)
    return "#{klass}##{name}" if klass
  end
  if self_receiver?(recv) && f['container']
    sep = f['method_kind'] == 'class' ? '.' : '#'
    return "#{f['container']}#{sep}#{name}"
  end
  if recv.is_a?(Array) && recv[0] == :var_ref && recv[1].is_a?(Array) && recv[1][0] == :@ident
    klass = (f['receiver_types'] || {})[recv[1][1]]
    return "#{klass}##{name}" if klass
  end
  klass = constant_path(recv)
  klass ? "#{klass}.#{name}" : name
end

def receiver_bindings(body)
  # Local `x = Clean.new` is a syntactic proof for a later `x.load`. Any untyped or differently typed
  # assignment to the same spelling makes it ambiguous and removes the binding.
  candidates = Hash.new { |h, k| h[k] = [] }
  visit = lambda do |node|
    next unless node.is_a?(Array)
    if node[0] == :assign
      lhs = []
      collect_names(node[1], lhs)
      if lhs.length == 1
        rhs_class = constant_path(node[2])
        candidates[lhs[0]] << rhs_class
      end
    end
    node.each do |child|
      visit.call(child) if child.is_a?(Array) && ![:def, :defs, :class, :module].include?(child[0])
    end
  end
  visit.call(body)
  candidates.each_with_object({}) do |(name, types), out|
    uniq = types.uniq
    out[name] = uniq[0] if uniq.length == 1 && uniq[0]
  end
end

def append_call(f, callee, args)
  bare = method_name(callee)
  return unless bare
  qualified = qualified_method_name(callee, f)
  call = { 'callee' => bare, 'args' => args }
  call['qualified_callee'] = qualified if qualified && qualified != bare
  f['calls'] << call
end

def collect_call_identities(node, out, f)
  return unless node.is_a?(Array)
  callee = case node[0]
           when :method_add_arg then node[1]
           when :call, :command_call then node
           when :fcall, :vcall then node
           end
  if callee
    identity = qualified_method_name(callee, f)
    if identity && (identity.include?('#') || identity.include?('.'))
      out << identity
    elsif identity
      # The Python orchestrator supplies the audit-relative file identity. Keep an explicit marker so
      # a bare call in an assignment/return can be qualified without confusing it with a same-spelled
      # local variable in the ordinary name footprint.
      out << "__lattice_local_call__:#{identity}"
    end
  end
  node.each do |child|
    collect_call_identities(child, out, f) if child.is_a?(Array) &&
      ![:def, :defs, :class, :module].include?(child[0])
  end
end

def walk(node, f)
  return unless node.is_a?(Array)
  case node[0]
  when :assign
    lhs = []; collect_names(node[1], lhs); rhs = []; collect_names(node[2], rhs)
    collect_call_identities(node[2], rhs, f)
    f['assigns'] << { 'lhs' => lhs, 'rhs' => rhs } unless lhs.empty?
  when :massign
    # `a, b = x, y` — Ripper: [:massign, [targets], [:mrhs_new_from_args, [rhs...]]]. Pair targets to rhs
    # POSITIONALLY when counts match, so a sanitizer on one rhs (`a = x.shellescape`) does NOT leak onto a
    # sibling target (a union would falsely mark b sanitized — a new FN). Fall back to union only for
    # splat / single-array-rhs / count-mismatch forms (FN-safe over-approximation).
    targets = node[1].is_a?(Array) ? node[1] : []
    rhs = node[2]
    rvals = nil
    if rhs.is_a?(Array) && rhs[0] == :mrhs_new_from_args
      # Ripper splits the LAST rhs value out: [:mrhs_new_from_args, [front-values...], last-value]
      front = rhs[1].is_a?(Array) ? rhs[1] : []
      rvals = front + (rhs[2] ? [rhs[2]] : [])
    end
    if rvals && rvals.length == targets.length
      targets.each_with_index do |t, i|
        tn = []; collect_names(t, tn)
        next if tn.empty?
        rn = []; collect_names(rvals[i], rn)
        f['assigns'] << { 'lhs' => tn, 'rhs' => rn }
      end
    else
      lhs = []; collect_names(node[1], lhs); r = []; collect_names(node[2], r)
      f['assigns'] << { 'lhs' => lhs, 'rhs' => r } unless lhs.empty?
    end
  when :opassign
    # `cmd += params[:host]` — Ripper: [:opassign, var_field, [:@op,"+="], rhs]. It READS and rebinds the
    # target, so the lhs's prior (tainted) value flows in too (analog of Python's ast.AugAssign).
    lhs = []; collect_names(node[1], lhs); rhs = []; collect_names(node[3], rhs)
    f['assigns'] << { 'lhs' => lhs, 'rhs' => (rhs + lhs).uniq } unless lhs.empty?
  when :binary
    # `cmd << params[:host]` — the shovel operator mutates the receiver in place, appending the rhs; model
    # it as `cmd gains rhs's taint`. Only `<<` (other binaries are pure expressions handled by recursion).
    if node[2] == :<<
      lhs = []; collect_names(node[1], lhs); rhs = []; collect_names(node[3], rhs)
      f['assigns'] << { 'lhs' => lhs, 'rhs' => (rhs + lhs).uniq } unless lhs.empty?
    end
  when :command
    a = []; collect_names(node[2], a); append_call(f, node[1], a)
  when :command_call
    a = []; collect_names(node[4], a); append_call(f, node, a)
  when :method_add_arg
    a = []; collect_names(node[2], a); append_call(f, node[1], a)
  when :call
    append_call(f, node, [])
  when :xstring_literal
    a = []; collect_names(node, a); f['calls'] << { 'callee' => '`backtick`', 'args' => a }
  end
  # do NOT descend into nested SCOPES — each is analyzed on its own pass, so a scope's calls/assigns
  # are attributed to exactly that scope (else <main> swept every method and conflated them).
  node.each { |c| walk(c, f) if c.is_a?(Array) && ![:def, :defs, :class, :module].include?(c[0]) }
end

SCOPE_TAGS = [:def, :defs, :class, :module].freeze
$funcs = []
def find_defs(node, scopes = [])
  return unless node.is_a?(Array)
  if node[0] == :class || node[0] == :module
    name = constant_path(node[1])
    nested = if name && name.include?('::')
               name.split('::')
             elsif name
               scopes + [name]
             else
               scopes
             end
    body = node[0] == :class ? node[3] : node[2]
    find_defs(body, nested)
    return
  elsif node[0] == :def
    name = node[1].is_a?(Array) && node[1][0] == :@ident ? node[1][1] : '<def>'
    container = scopes.empty? ? nil : scopes.join('::')
    qualified = container ? "#{container}##{name}" : name
    f = { 'name' => name, 'qualified_name' => qualified, 'container' => container,
          'method_kind' => container ? 'instance' : 'function', 'params' => param_names(node[2]),
          'assigns' => [], 'calls' => [] }
    f['receiver_types'] = receiver_bindings(node[3])
    f['returns'] = return_names(node[3], f)
    walk(node[3], f)              # bodystmt
    $funcs << f
  elsif node[0] == :defs          # `def self.run` / `def Obj.method` — a class/singleton method
    name = node[3].is_a?(Array) && node[3][0] == :@ident ? node[3][1] : '<def>'
    lexical = scopes.empty? ? nil : scopes.join('::')
    receiver = self_receiver?(node[1]) ? lexical : constant_path(node[1])
    qualified = receiver ? "#{receiver}.#{name}" : name
    f = { 'name' => name, 'qualified_name' => qualified, 'container' => receiver,
          'method_kind' => receiver ? 'class' : 'function', 'params' => param_names(node[4]),
          'assigns' => [], 'calls' => [] }
    f['receiver_types'] = receiver_bindings(node[5])
    f['returns'] = return_names(node[5], f)
    walk(node[5], f)              # bodystmt (after recv, period, ident, params)
    $funcs << f
  end
  # recurse to find scopes nested inside classes/modules/methods
  node.each { |c| find_defs(c, scopes) if c.is_a?(Array) }
end

begin
  sexp = Ripper.sexp(File.read(ARGV[0]))
  if sexp.nil? then STDERR.puts 'PARSE_ERROR'; exit 2 end
  # module-level (top-level statements outside any def)
  top = { 'name' => '<main>', 'qualified_name' => '<main>', 'assigns' => [], 'calls' => [] }
  walk(sexp, top)
  $funcs << top
  find_defs(sexp)
  puts JSON.generate($funcs)
rescue => e
  STDERR.puts "PARSE_ERROR: #{e}"; exit 2
end
