# ADR 0004: Structured Error Handling

## Status

Accepted

## Context

BPF operations can fail in many ways:
- Permission errors (missing CAP_BPF)
- Verifier rejections (unsafe program)
- Resource limits (too many maps/programs)
- System errors (ENOMEM, etc.)

Different error types require different handling:
- Permission errors: Need capability setup
- Verifier errors: Need program fixes
- Resource errors: Need cleanup/limits adjustment

## Decision

### Structured Exception Info

All BPF errors are thrown as `ex-info` with structured data:
```clojure
(throw (ex-info "BPF syscall failed"
                {:type :bpf-error
                 :category :permission
                 :errno 1
                 :errno-keyword :eperm
                 :operation :prog-load
                 :details {...}}))
```

### Error Categories

We define categories in `clj-ebpf.errors`:
- `:permission` - CAP_BPF, CAP_SYS_ADMIN issues
- `:verifier` - Program rejected by verifier
- `:resource` - Resource limits exceeded
- `:not-found` - Map/program not found
- `:invalid` - Invalid arguments
- `:system` - Other system errors

### Predicate Functions

```clojure
(errors/permission-error? e)  ; Check if permission issue
(errors/verifier-error? e)    ; Check if verifier rejection
(errors/resource-error? e)    ; Check if resource limit
```

### Error Formatting

```clojure
(errors/format-error e)       ; Human-readable error message
(errors/suggest-fix e)        ; Suggested remediation
```

### Verifier Log Integration

For verifier errors, we capture and parse the verifier log:
```clojure
(try
  (load-program prog :xdp)
  (catch Exception e
    (when (errors/verifier-error? e)
      (println (:verifier-log (ex-data e))))))
```

## Consequences

### Positive

- **Actionable errors**: Clear indication of what went wrong
- **Programmatic handling**: Can catch and handle specific error types
- **Debugging aid**: Verifier logs included in errors
- **User-friendly**: Suggested fixes for common issues

### Negative

- **Verbosity**: More code to create structured errors
- **Maintenance**: Need to update error categories for new error types

## Error Handling Pattern

```clojure
(try
  (maps/create {:type :hash :key-size 4 :value-size 8 :max-entries 1000000})
  (catch Exception e
    (cond
      (errors/permission-error? e)
      (println "Need CAP_BPF capability")

      (errors/resource-error? e)
      (println "Reduce max-entries or increase limits")

      :else
      (throw e))))
```

## References

- [Linux errno values](https://man7.org/linux/man-pages/man3/errno.3.html)
- [BPF verifier](https://www.kernel.org/doc/html/latest/bpf/verifier.html)
