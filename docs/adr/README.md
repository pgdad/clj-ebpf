# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) documenting significant design decisions in clj-ebpf.

## What is an ADR?

An Architecture Decision Record captures an important architectural decision made along with its context and consequences. ADRs help:

- Document why decisions were made
- Onboard new contributors
- Revisit decisions when context changes
- Maintain consistency across the project

## ADR Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-use-panama-ffi.md) | Use Java Panama FFI for Syscall Interface | Accepted |
| [0002](0002-dsl-design.md) | Domain Specific Language for BPF Instruction Generation | Accepted |
| [0003](0003-map-operations.md) | BPF Map Operations Design | Accepted |
| [0004](0004-error-handling.md) | Structured Error Handling | Accepted |
| [0005](0005-testing-strategy.md) | Testing Strategy | Accepted |

## ADR Status Values

- **Proposed**: Under discussion
- **Accepted**: Decision made and in effect
- **Deprecated**: No longer applies but kept for history
- **Superseded**: Replaced by a newer ADR

## Creating a New ADR

1. Copy the template below
2. Number it sequentially (e.g., `0006-*.md`)
3. Fill in the sections
4. Submit for review

### Template

```markdown
# ADR NNNN: Title

## Status

Proposed | Accepted | Deprecated | Superseded by [ADR NNNN](link)

## Context

What is the issue we're addressing? What forces are at play?

## Decision

What is the decision? What did we decide to do?

## Consequences

What are the positive and negative consequences of this decision?
```

## References

- [ADR GitHub Organization](https://adr.github.io/)
- [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
