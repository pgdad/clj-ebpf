# clj-ebpf Documentation

Comprehensive documentation for clj-ebpf, a pure Clojure library for eBPF programming.

## Getting Started

Start with the main [README](../README.md) in the project root for:
- Installation and setup
- Quick start guide
- System requirements
- Basic usage examples

## Guides

### Quick Start

#### [High-Level Declarative Macros](guides/macros.md)

Learn to write BPF applications with 60% less code using the declarative macros:

**Topics Covered:**
- `defmap-spec` - Define reusable BPF map specifications
- `defprogram` - Define BPF programs declaratively with DSL
- `with-bpf-script` - Automatic lifecycle management
- Attachment types (XDP, TC, kprobe, tracepoint, uprobe, cgroup, LSM)
- Best practices and when to use macros vs lower-level API

**Target Audience:**
- New clj-ebpf users wanting a quick start
- Developers preferring declarative, Clojure-idiomatic APIs
- REPL-driven development workflows

See also: [Macros Tutorial](../tutorials/quick-start-macros.md) for hands-on examples.

### Extending clj-ebpf

#### [Adding New Helper Functions](adding-new-helpers.md)

Learn how to extend clj-ebpf with new BPF helper functions as they're added to the Linux kernel.

**Topics Covered:**
- Helper function structure and metadata
- Step-by-step guide to adding new helpers
- Using custom helpers in BPF programs
- Helper query and compatibility checking
- Integration with the DSL
- Complete working examples
- Best practices and testing strategies

**Target Audience:**
- Developers wanting to use bleeding-edge kernel features
- Contributors adding support for new kernel versions
- Anyone needing helpers not yet in clj-ebpf

**Prerequisites:**
- Basic understanding of BPF concepts
- Familiarity with Clojure
- Knowledge of BPF helper functions

## Examples

See the [`examples/`](../examples/) directory for runnable code:

- **[macro_dsl.clj](../examples/macro_dsl.clj)** - Comprehensive examples of high-level declarative macros
- **[simple_kprobe.clj](../examples/simple_kprobe.clj)** - Basic kprobe attachment and tracing (shows both traditional and macro approaches)
- **[execve_tracer.clj](../examples/execve_tracer.clj)** - System call tracing with BPF maps
- **[custom_helpers.clj](../examples/custom_helpers.clj)** - Complete example of defining and using custom helpers

Run examples:
```bash
# Custom helpers demo (no root required)
clj -M -m examples.custom-helpers

# System call tracing (requires root)
sudo clj -M -m examples.execve-tracer trace
```

## API Reference

### Core Namespaces

- **`clj-ebpf.core`** - Main public API
  - Map operations (create, update, lookup, delete)
  - Program loading and attachment
  - Event processing
  - Resource management macros
  - Re-exports from `clj-ebpf.macros`

- **`clj-ebpf.macros`** - High-level declarative macros
  - `defmap-spec` - Define reusable map specifications
  - `defprogram` - Define programs with DSL body
  - `with-bpf-script` - Lifecycle management
  - `load-defprogram`, `create-defmap` - Convenience functions

- **`clj-ebpf.helpers`** - BPF helper function registry
  - 200+ helper definitions with metadata
  - Compatibility checking
  - Query and discovery functions
  - Category-based organization

- **`clj-ebpf.dsl`** - BPF assembly DSL
  - Instruction builders (mov, add, jmp, etc.)
  - Register management
  - Helper function calls
  - Program assembly

- **`clj-ebpf.maps`** - BPF map types and operations
  - Hash, array, LRU, per-CPU maps
  - Stack, queue, LPM trie maps
  - Ring buffers
  - Batch operations

- **`clj-ebpf.programs`** - Program types and attachment
  - XDP, TC, kprobe, tracepoint
  - LSM, cgroup programs
  - Program lifecycle management

- **`clj-ebpf.btf`** - BTF (BPF Type Format) support
  - Type introspection
  - Struct/enum parsing
  - CO-RE support

- **`clj-ebpf.relocate`** - CO-RE relocations
  - Portable BPF programs
  - Field offset relocations
  - Type compatibility

## Tutorials

See [`tutorials/`](../tutorials/) for a comprehensive 25-chapter tutorial series:

- **Part I: Fundamentals** (Chapters 1-6)
- **Part II: Core Concepts** (Chapters 7-10)
- **Part III: Advanced Topics** (Chapters 11-14)
- **Part IV: Real-World Applications** (Chapters 15-22)
- **Part V: Production & Best Practices** (Chapters 23-25)

Start with [Tutorial Introduction](../tutorials/README.md).

## Architecture

clj-ebpf uses a layered architecture:

```
┌─────────────────────────────────────────┐
│      Core API (clj-ebpf.core)           │
│   User-facing facade and conveniences   │
└───────────────┬─────────────────────────┘
                │
┌───────────────┴─────────────────────────┐
│        Domain Layer                      │
│  Maps | Programs | Events | DSL | BTF   │
└───────────────┬─────────────────────────┘
                │
┌───────────────┴─────────────────────────┐
│      Utils Layer (clj-ebpf.utils)       │
│  Memory | Serialization | System Utils  │
└───────────────┬─────────────────────────┘
                │
┌───────────────┴─────────────────────────┐
│   Syscall Layer (clj-ebpf.syscall)      │
│     Direct bpf() syscall via Panama     │
└─────────────────────────────────────────┘
```

**Design Principles:**
- Zero external dependencies (Panama FFI only)
- Direct syscall access for maximum control
- Idiomatic Clojure APIs
- Comprehensive error handling
- Resource safety with macros

## Development

### Building from Source

```bash
git clone https://github.com/yourusername/clj-ebpf
cd clj-ebpf
clj -M:test  # Run tests
```

### Running Tests

```bash
# Unit tests (no root required)
clj -M:test

# Integration tests (requires root and BPF support)
sudo clj -M:test

# Specific test namespace
clj -M:test -n clj-ebpf.helpers-test
```

### Contributing

Contributions are welcome! Areas for contribution:
- Adding new BPF helper functions
- Improving documentation
- Writing examples and tutorials
- Bug fixes and performance improvements
- Test coverage

See the main README for contribution guidelines.

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with `sudo` or set capabilities
   ```bash
   sudo setcap cap_bpf,cap_perfmon+ep $(which java)
   ```

2. **BPF Filesystem Not Mounted**:
   ```bash
   sudo mount -t bpf bpf /sys/fs/bpf
   ```

3. **Kernel Version Too Old**: Upgrade to kernel 4.14+ (5.8+ recommended)

4. **Program Load Failed**: Check verifier log in exception data

5. **Helper Not Available**: Check kernel version compatibility
   ```clojure
   (require '[clj-ebpf.helpers :as helpers])
   (helpers/helper-compatible? :my-helper :xdp "6.3")
   ```

## Resources

### External Documentation

- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [BPF Features by Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [eBPF Summit](https://ebpf.io/summit-2024/)
- [Cilium eBPF Guide](https://docs.cilium.io/en/stable/bpf/)
- [libbpf Documentation](https://github.com/libbpf/libbpf)

### Related Projects

- [libbpf](https://github.com/libbpf/libbpf) - C library for BPF
- [aya](https://github.com/aya-rs/aya) - Rust BPF library
- [bcc](https://github.com/iovisor/bcc) - BPF Compiler Collection
- [gobpf](https://github.com/iovisor/gobpf) - Go BPF library

## License

Copyright © 2025

Distributed under the Eclipse Public License version 1.0.

## Questions?

- 📖 Check this documentation
- 💬 Open an issue on GitHub
- 📧 Contact the maintainers
- 🎓 Review the tutorial series
- 🔍 Browse the examples

---

Last updated: November 2024
