# ADR 0003: BPF Map Operations Design

## Status

Accepted

## Context

BPF maps are kernel data structures that allow:
- Communication between BPF programs and userspace
- State sharing between BPF program invocations
- Inter-CPU data synchronization

We needed to design an API that:
- Supports all common map types (hash, array, ring buffer, etc.)
- Is efficient for bulk operations
- Handles memory correctly (no leaks)
- Provides Clojure-idiomatic interfaces

## Decision

### Map Types as Keywords

Map types are specified as keywords:
```clojure
(maps/create {:type :hash :key-size 4 :value-size 8 :max-entries 1024})
(maps/create {:type :ringbuf :max-entries 4096})
```

### Immutable-Style API

Map operations return results rather than mutating in place:
```clojure
(maps/lookup map key)     ; Returns value or nil
(maps/update! map key val) ; Returns true/false
(maps/delete! map key)    ; Returns true/false
```

### Batch Operations

For bulk operations, we provide batch functions:
```clojure
(maps/lookup-batch map keys)   ; Returns seq of values
(maps/update-batch! map pairs) ; Updates multiple key-value pairs
```

### Lazy Iteration

Map iteration is lazy to handle large maps:
```clojure
(maps/entries-seq map) ; Returns lazy seq of [key value] pairs
```

### Resource Management

Maps are resources that must be closed:
```clojure
(with-open [m (maps/create {...})]
  (maps/update! m key val))
```

Or using the macro:
```clojure
(maps/with-map [m {:type :hash ...}]
  (maps/update! m key val))
```

## Consequences

### Positive

- **Type safety**: Map types validated at creation time
- **Memory safety**: Automatic cleanup with `with-open`/`with-map`
- **Performance**: Batch operations minimize syscall overhead
- **Clojure-idiomatic**: Works with standard Clojure patterns
- **Lazy sequences**: Handles large maps without memory issues

### Negative

- **Verbosity**: More explicit than mutable map APIs
- **Learning curve**: Different from Java/C map APIs
- **Overhead**: Some abstraction overhead for simple operations

## Map Types Supported

| Type | Description |
|------|-------------|
| `:hash` | Hash table |
| `:array` | Array with integer keys |
| `:percpu-hash` | Per-CPU hash table |
| `:percpu-array` | Per-CPU array |
| `:lru-hash` | LRU hash table |
| `:lru-percpu-hash` | Per-CPU LRU hash |
| `:ringbuf` | Ring buffer for events |
| `:stack` | LIFO stack |
| `:queue` | FIFO queue |
| `:lpm-trie` | Longest prefix match trie |
| `:hash-of-maps` | Hash containing map FDs |
| `:array-of-maps` | Array containing map FDs |

## References

- [BPF maps documentation](https://www.kernel.org/doc/html/latest/bpf/maps.html)
- [BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html)
