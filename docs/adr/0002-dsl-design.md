# ADR 0002: Domain Specific Language for BPF Instruction Generation

## Status

Accepted

## Context

BPF programs are typically written in C and compiled with LLVM/Clang to BPF bytecode. However, this requires:
- External toolchain installation
- Separate compilation step
- C language expertise

We wanted to provide a way to write BPF programs directly in Clojure without external tools.

## Decision

We created a DSL (Domain Specific Language) that:

1. **Maps directly to BPF instructions**: Each DSL function produces one or more BPF instructions
2. **Uses Clojure idioms**: Keywords for registers (`:r0`, `:r1`), vectors for instruction sequences
3. **Provides multiple abstraction levels**:
   - `clj-ebpf.dsl.instructions` - Raw instruction encoding
   - `clj-ebpf.dsl.alu`, `.mem`, `.jump`, `.atomic` - Categorized operations
   - `clj-ebpf.dsl.core` - Unified API with `assemble` function

Example:
```clojure
(require '[clj-ebpf.dsl.core :as dsl])

(def program
  (dsl/assemble
    [(dsl/mov :r0 2)      ; Set return value
     (dsl/exit-insn)]))   ; Exit program
```

## Consequences

### Positive

- **No external toolchain**: Pure Clojure, no LLVM required
- **Runtime program generation**: Can create BPF programs dynamically
- **Transparent mapping**: Easy to understand what bytecode is generated
- **Verifier feedback**: Errors map directly to DSL operations
- **REPL-friendly**: Interactive development of BPF programs

### Negative

- **Manual optimization**: No compiler optimizations, developers must optimize manually
- **Limited features**: No BTF generation, no CO-RE (Compile Once Run Everywhere)
- **Learning curve**: Developers need to understand BPF instruction set
- **No high-level abstractions**: No if-else, loops must be done with jumps

### Trade-offs

We chose transparency over abstraction. The DSL shows exactly what BPF instructions are generated, which helps with debugging verifier errors. Higher-level abstractions can be built on top.

## Alternatives Considered

1. **Embed LLVM**: Too heavy, defeats purpose of pure-Clojure solution
2. **Parse C code**: Complex, still requires understanding C
3. **High-level Clojure DSL**: Would hide important details, harder to debug

## References

- [BPF Instruction Set Architecture](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html)
- [BPF Design Q&A](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html)
