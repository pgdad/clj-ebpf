# Lab 1.1: Hello eBPF

**Objective**: Write, load, and run your first eBPF program

**Duration**: 30 minutes

## Overview

In this lab, you'll create the simplest possible eBPF program - one that just returns successfully. This introduces you to the basic workflow of eBPF development with clj-ebpf.

## What You'll Learn

- How to write a minimal BPF program
- How to assemble DSL code to BPF bytecode
- How to load a program into the kernel
- How to verify program loading
- Basic eBPF program lifecycle

## Theory

Every BPF program must:
1. End with an exit instruction
2. Return a value in register r0
3. Pass the verifier's safety checks

The simplest BPF program:
```
r0 = 0      ; Set return value to 0
exit        ; Exit program
```

## Implementation

### Step 1: Create the Project

Create `lab-1-1.clj`:
```clojure
(ns lab-1-1-hello-ebpf
  "Lab 1.1: Hello eBPF - Your first BPF program"
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.arch :as arch]
            [clj-ebpf.errors :as errors]))

(defn -main []
  (println "=== Lab 1.1: Hello eBPF ===\n")

  ;; Step 0: Show platform information (using clj-ebpf.arch)
  (println "Step 0: Platform Information")
  (println "Architecture:" arch/arch-name)
  (println "Arch keyword:" arch/current-arch)
  (println "BPF syscall number:" (arch/get-syscall-nr :bpf))
  (println "")

  ;; Step 1: Initialize clj-ebpf
  (println "Step 1: Initializing clj-ebpf...")
  (let [init-result (bpf/init!)]
    (println "Kernel version:" (format "0x%06x" (:kernel-version init-result)))
    (println "BPF filesystem:" (if (:bpf-fs-mounted init-result)
                                 "mounted ✓"
                                 "NOT mounted ✗")))

  ;; Step 2: Create the simplest BPF program
  (println "\nStep 2: Creating BPF program...")
  (def hello-program
    (bpf/assemble
      [;; mov r0, 0  - Set return value to 0
       (bpf/mov :r0 0)
       ;; exit - Return from program
       (bpf/exit-insn)]))

  (println "Program assembled successfully!")
  (println "Program size:" (count hello-program) "bytes")
  (println "Instructions:" (/ (count hello-program) 8))

  ;; Step 3: Load the program into the kernel
  (println "\nStep 3: Loading program into kernel...")
  (try
    (let [prog-fd (bpf/load-program hello-program :socket-filter)]
      (println "Program loaded successfully!")
      (println "Program FD:" prog-fd)

      ;; Step 4: Verify the program
      (println "\nStep 4: Verifying program...")
      (println "✓ Program passed verifier")
      (println "✓ Program is valid")

      ;; Step 5: Clean up
      (println "\nStep 5: Cleaning up...")
      (bpf/close-program prog-fd)
      (println "✓ Program unloaded"))

    (catch Exception e
      (println "✗ Error:" (.getMessage e))

      ;; Use structured error handling from clj-ebpf.errors
      (println "\n" (errors/format-error e))

      (cond
        (errors/permission-error? e)
        (do
          (println "\nPermission Error - Try:")
          (println "- Run with sudo")
          (println "- Add CAP_BPF capability: sudo setcap cap_bpf+eip $(which java)"))

        (errors/verifier-error? e)
        (do
          (println "\nVerifier Error - Check:")
          (println "- Program ends with exit instruction")
          (println "- All registers initialized before use"))

        :else
        (do
          (println "\nTroubleshooting:")
          (println "- Check if BPF filesystem is mounted: ls /sys/fs/bpf")
          (println "- Check kernel version: uname -r (need 5.8+)")))))

  (println "\n=== Lab 1.1 Complete! ==="))
```

### Step 2: Run the Lab

```bash
cd tutorials/part-1-fundamentals/chapter-01/labs
clojure -M lab-1-1.clj
```

### Expected Output

```
=== Lab 1.1: Hello eBPF ===

Step 0: Platform Information
Architecture: x86-64 (AMD64)
Arch keyword: :x86_64
BPF syscall number: 321

Step 1: Initializing clj-ebpf...
Kernel version: 0x050800
BPF filesystem: mounted ✓

Step 2: Creating BPF program...
Program assembled successfully!
Program size: 16 bytes
Instructions: 2

Step 3: Loading program into kernel...
Program loaded successfully!
Program FD: 3

Step 4: Verifying program...
✓ Program passed verifier
✓ Program is valid

Step 5: Cleaning up...
✓ Program unloaded

=== Lab 1.1 Complete! ===
```

## Understanding the Code

### The Program

```clojure
(bpf/assemble
  [(bpf/mov :r0 0)      ; Move immediate value 0 into register r0
   (bpf/exit-insn)])    ; Exit program
```

This creates:
1. **MOV instruction**: Sets r0 (return register) to 0
2. **EXIT instruction**: Returns from the BPF program

### The Bytecode

The `assemble` function converts DSL to BPF bytecode:
- MOV r0, 0 → `b7 00 00 00 00 00 00 00` (8 bytes)
- EXIT → `95 00 00 00 00 00 00 00` (8 bytes)
- Total: 16 bytes

### Program Loading

```clojure
(bpf/load-program hello-program :socket-filter)
```

This:
1. Sends bytecode to kernel via bpf() syscall
2. Kernel verifies the program
3. Kernel JIT-compiles to native code
4. Returns a file descriptor

## Experiments

Try these variations to learn more:

### Experiment 1: Change Return Value

```clojure
(bpf/assemble
  [(bpf/mov :r0 42)     ; Return 42 instead of 0
   (bpf/exit-insn)])
```

### Experiment 2: Use Multiple Instructions

```clojure
(bpf/assemble
  [(bpf/mov :r0 10)     ; r0 = 10
   (bpf/add :r0 32)     ; r0 = r0 + 32 = 42
   (bpf/exit-insn)])    ; return 42
```

### Experiment 3: Invalid Program (Will Fail Verification)

```clojure
;; Missing exit - verifier will reject
(bpf/assemble
  [(bpf/mov :r0 0)])
```

## Troubleshooting

### Error: "Permission denied"

**Solution**: Run with sudo or grant CAP_BPF capability:
```bash
sudo setcap cap_bpf,cap_perfmon+eip $(which java)
```

### Error: "BPF filesystem not mounted"

**Solution**: Mount the BPF filesystem:
```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

### Error: "Invalid instruction"

**Solution**: Check that your program:
- Ends with `exit-insn`
- Uses valid register names (:r0 through :r10)
- Uses valid instruction formats

## Key Takeaways

✅ BPF programs must end with an exit instruction
✅ Return values go in register r0
✅ The verifier ensures program safety
✅ Programs are JIT-compiled for performance
✅ File descriptors represent loaded programs
✅ Use `clj-ebpf.arch` for platform-specific information
✅ Use `clj-ebpf.errors` for structured error handling

## clj-ebpf Modules Introduced

| Module | Purpose |
|--------|---------|
| `clj-ebpf.core` | Main API for loading/managing BPF programs |
| `clj-ebpf.arch` | Architecture detection, syscall numbers |
| `clj-ebpf.errors` | Structured error handling |

## Alternative DSL Imports

For more focused code, you can import DSL submodules directly:

```clojure
;; Instead of using everything from clj-ebpf.core:
(:require [clj-ebpf.core :as bpf])

;; You can import specific DSL modules:
(:require [clj-ebpf.dsl.core :as dsl]     ; Unified DSL
          [clj-ebpf.dsl.alu :as alu]      ; ALU operations
          [clj-ebpf.dsl.mem :as mem]      ; Memory operations
          [clj-ebpf.dsl.jump :as jmp])    ; Jump/control flow

;; Then use them directly:
(dsl/assemble
  [(alu/mov :r0 0)
   (jmp/exit-insn)])
```

## Next Steps

- **Next Lab**: [Lab 1.2 - System Information](lab-1-2-system-info.md)
- **Chapter**: [Chapter 1 - Introduction](../README.md)

## Challenge

Create a BPF program that:
1. Adds two numbers
2. Multiplies the result by 3
3. Returns the value

Solution in: [solutions/lab-1-1-challenge.clj](../solutions/lab-1-1-challenge.clj)
