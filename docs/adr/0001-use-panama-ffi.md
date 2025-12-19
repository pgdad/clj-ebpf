# ADR 0001: Use Java Panama FFI for Syscall Interface

## Status

Accepted

## Context

clj-ebpf needs to make Linux syscalls to interact with the BPF subsystem. Traditional approaches include:

1. **JNI (Java Native Interface)** - Requires compiling C code, platform-specific binaries
2. **JNA (Java Native Access)** - Runtime library, slower than JNI
3. **Panama FFI (Foreign Function & Memory API)** - Java 25+ standard API

We needed a solution that:
- Works across architectures (x86_64, aarch64, riscv64)
- Doesn't require external C compilation
- Has good performance for syscall-heavy operations
- Is a stable, supported API

## Decision

We chose to use Java Panama FFI (Project Panama's Foreign Function & Memory API) for all native interactions.

## Consequences

### Positive

- **No external dependencies**: No native libraries to compile or distribute
- **Pure Java/Clojure**: The entire library is JVM-only code
- **Multi-architecture support**: Panama works on any platform Java supports
- **Performance**: Panama's direct memory access is efficient for BPF operations
- **Safety**: Panama provides memory safety checks

### Negative

- **Java 25+ required**: Users must use Java 25 or later for full support
- **API changes**: Panama was in preview before Java 21; we use the stable API from Java 25
- **Learning curve**: Panama has its own idioms for memory management

### Mitigations

- Clear documentation of Java version requirements
- Use of `Arena` for automatic memory management
- Wrapper functions to hide Panama complexity from library users

## References

- [JEP 442: Foreign Function & Memory API (Third Preview)](https://openjdk.org/jeps/442)
- [JEP 454: Foreign Function & Memory API (Final)](https://openjdk.org/jeps/454)
