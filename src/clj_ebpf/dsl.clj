(ns clj-ebpf.dsl
  "Idiomatic Clojure DSL for BPF programming"
  (:require [clj-ebpf.utils :as utils]))

;; ============================================================================
;; BPF Instruction Encoding
;; ============================================================================

;; BPF instruction format (64-bit):
;; |immediate:32|offset:16|src_reg:4|dst_reg:4|opcode:8|

;; ============================================================================
;; Instruction Classes
;; ============================================================================

(def instruction-class
  "BPF instruction classes (3 LSB bits of opcode)"
  {:ld     0x00  ; Non-standard load
   :ldx    0x01  ; Load into register
   :st     0x02  ; Store from immediate
   :stx    0x03  ; Store from register
   :alu    0x04  ; 32-bit arithmetic
   :jmp    0x05  ; 64-bit jump
   :jmp32  0x06  ; 32-bit jump
   :alu64  0x07  ; 64-bit arithmetic
   })

;; ============================================================================
;; ALU/ALU64 Operations
;; ============================================================================

(def alu-op
  "ALU operation codes (bits 4-7 of opcode)"
  {:add   0x00
   :sub   0x10
   :mul   0x20
   :div   0x30
   :or    0x40
   :and   0x50
   :lsh   0x60  ; Left shift
   :rsh   0x70  ; Right shift (logical)
   :neg   0x80
   :mod   0x90
   :xor   0xa0
   :mov   0xb0
   :arsh  0xc0  ; Arithmetic right shift
   :end   0xd0  ; Byte swap (endianness)
   })

;; ============================================================================
;; Jump Operations
;; ============================================================================

(def jmp-op
  "Jump operation codes (bits 4-7 of opcode)"
  {:ja    0x00  ; Unconditional jump (JMP only)
   :jeq   0x10  ; Jump if equal
   :jgt   0x20  ; Jump if greater (unsigned)
   :jge   0x30  ; Jump if greater or equal (unsigned)
   :jset  0x40  ; Jump if bitwise AND is non-zero
   :jne   0x50  ; Jump if not equal
   :jsgt  0x60  ; Jump if greater (signed)
   :jsge  0x70  ; Jump if greater or equal (signed)
   :call  0x80  ; Function/helper call
   :exit  0x90  ; Exit program (JMP only)
   :jlt   0xa0  ; Jump if less than (unsigned)
   :jle   0xb0  ; Jump if less or equal (unsigned)
   :jslt  0xc0  ; Jump if less than (signed)
   :jsle  0xd0  ; Jump if less or equal (signed)
   })

;; ============================================================================
;; Load/Store Size
;; ============================================================================

(def load-store-size
  "Load/store size modifiers (bits 3-4 of opcode)"
  {:w   0x00  ; 4 bytes (word)
   :h   0x08  ; 2 bytes (half-word)
   :b   0x10  ; 1 byte
   :dw  0x18  ; 8 bytes (double-word)
   })

;; ============================================================================
;; Load/Store Mode
;; ============================================================================

(def load-store-mode
  "Load/store mode modifiers (bits 5-7 of opcode)"
  {:imm    0x00  ; 64-bit immediate
   :abs    0x20  ; Packet access (absolute)
   :ind    0x40  ; Packet access (indirect)
   :mem    0x60  ; Regular memory
   :atomic 0xc0  ; Atomic operations
   })

;; ============================================================================
;; Source Operand
;; ============================================================================

(def source-operand
  "Source operand selector (bit 3 of opcode)"
  {:k 0x00  ; 32-bit immediate value
   :x 0x08  ; Source register
   })

;; ============================================================================
;; Registers
;; ============================================================================

(def registers
  "BPF register mapping"
  {:r0  0  ; Return value / exit code
   :r1  1  ; Function argument 1
   :r2  2  ; Function argument 2
   :r3  3  ; Function argument 3
   :r4  4  ; Function argument 4
   :r5  5  ; Function argument 5
   :r6  6  ; Callee-saved
   :r7  7  ; Callee-saved
   :r8  8  ; Callee-saved
   :r9  9  ; Callee-saved
   :r10 10  ; Read-only frame pointer
   })

;; ============================================================================
;; Helper Functions
;; ============================================================================

(def bpf-helpers
  "Common BPF helper function IDs"
  {:map-lookup-elem        1
   :map-update-elem        2
   :map-delete-elem        3
   :probe-read             4
   :ktime-get-ns           5
   :trace-printk           6
   :get-prandom-u32        7
   :get-smp-processor-id   8
   :skb-store-bytes        9
   :l3-csum-replace        10
   :l4-csum-replace        11
   :tail-call              12
   :clone-redirect         13
   :get-current-pid-tgid   14
   :get-current-uid-gid    15
   :get-current-comm       16
   :get-cgroup-classid     17
   :skb-vlan-push          18
   :skb-vlan-pop           19
   :skb-get-tunnel-key     20
   :skb-set-tunnel-key     21
   :perf-event-read        22
   :redirect               23
   :get-route-realm        24
   :perf-event-output      25
   :skb-load-bytes         26
   :get-stackid            27
   :csum-diff              28
   :skb-get-tunnel-opt     29
   :skb-set-tunnel-opt     30
   :skb-change-proto       31
   :skb-change-type        32
   :skb-under-cgroup       33
   :get-hash-recalc        34
   :get-current-task       35
   :probe-write-user       36
   :current-task-under-cgroup 37
   :skb-change-tail        38
   :skb-pull-data          39
   :csum-update            40
   :set-hash-invalid       41
   :get-numa-node-id       42
   :skb-change-head        43
   :xdp-adjust-head        44
   :probe-read-str         45
   :get-socket-cookie      46
   :get-socket-uid         47
   :set-hash               48
   })

;; ============================================================================
;; XDP Action Codes
;; ============================================================================

(def xdp-action
  "XDP program return codes"
  {:aborted  0  ; Error, drop packet
   :drop     1  ; Drop packet
   :pass     2  ; Pass to network stack
   :tx       3  ; Transmit back out same interface
   :redirect 4  ; Redirect to different interface
   })

;; ============================================================================
;; TC Action Codes
;; ============================================================================

(def tc-action
  "TC program return codes"
  {:unspec     -1  ; Continue with next rule
   :ok         0   ; Pass packet
   :reclassify 1   ; Reclassify packet
   :shot       2   ; Drop packet
   :pipe       3   ; Continue with next action
   :stolen     4   ; Consume packet
   :queued     5   ; Packet queued
   :repeat     6   ; Repeat action
   :redirect   7   ; Redirect packet
   })

;; ============================================================================
;; Instruction Builder
;; ============================================================================

(defn- resolve-register
  "Resolve register keyword to numeric value"
  [reg]
  (cond
    (keyword? reg) (get registers reg)
    (number? reg) reg
    :else (throw (ex-info "Invalid register" {:register reg}))))

(defn- build-instruction
  "Build a single 64-bit BPF instruction.

  Parameters:
  - opcode: 8-bit opcode
  - dst: 4-bit destination register
  - src: 4-bit source register
  - offset: 16-bit offset (signed)
  - imm: 32-bit immediate value (signed)

  Returns byte array (8 bytes)"
  [opcode dst src offset imm]
  (let [opcode (unchecked-byte (bit-and opcode 0xFF))
        regs (unchecked-byte (bit-or (bit-shift-left (bit-and src 0xF) 4)
                                     (bit-and dst 0xF)))
        offset-bytes (utils/pack-struct [[:i16 offset]])
        imm-bytes (utils/pack-struct [[:i32 imm]])]
    (byte-array (concat [opcode regs]
                       offset-bytes
                       imm-bytes))))

;; ============================================================================
;; ALU/ALU64 Instructions
;; ============================================================================

(defn alu-reg
  "ALU operation with register operand (64-bit).

  Example:
    (alu-reg :add :r0 :r1)  ; r0 += r1"
  [op dst src]
  (let [opcode (bit-or (get alu-op op)
                      (get source-operand :x)
                      (get instruction-class :alu64))
        dst-reg (resolve-register dst)
        src-reg (resolve-register src)]
    (build-instruction opcode dst-reg src-reg 0 0)))

(defn alu-imm
  "ALU operation with immediate operand (64-bit).

  Example:
    (alu-imm :add :r0 10)  ; r0 += 10"
  [op dst imm]
  (let [opcode (bit-or (get alu-op op)
                      (get source-operand :k)
                      (get instruction-class :alu64))
        dst-reg (resolve-register dst)]
    (build-instruction opcode dst-reg 0 0 imm)))

(defn alu32-reg
  "ALU operation with register operand (32-bit).

  Example:
    (alu32-reg :add :r0 :r1)  ; r0 = (u32)(r0 + r1)"
  [op dst src]
  (let [opcode (bit-or (get alu-op op)
                      (get source-operand :x)
                      (get instruction-class :alu))
        dst-reg (resolve-register dst)
        src-reg (resolve-register src)]
    (build-instruction opcode dst-reg src-reg 0 0)))

(defn alu32-imm
  "ALU operation with immediate operand (32-bit).

  Example:
    (alu32-imm :add :r0 10)  ; r0 = (u32)(r0 + 10)"
  [op dst imm]
  (let [opcode (bit-or (get alu-op op)
                      (get source-operand :k)
                      (get instruction-class :alu))
        dst-reg (resolve-register dst)]
    (build-instruction opcode dst-reg 0 0 imm)))

;; ============================================================================
;; Convenience ALU Instructions
;; ============================================================================

(defn mov
  "Move immediate to register (64-bit).

  Example:
    (mov :r0 42)  ; r0 = 42"
  [dst imm]
  (alu-imm :mov dst imm))

(defn mov-reg
  "Move register to register (64-bit).

  Example:
    (mov-reg :r0 :r1)  ; r0 = r1"
  [dst src]
  (alu-reg :mov dst src))

(defn add
  "Add immediate to register (64-bit).

  Example:
    (add :r0 10)  ; r0 += 10"
  [dst imm]
  (alu-imm :add dst imm))

(defn add-reg
  "Add register to register (64-bit).

  Example:
    (add-reg :r0 :r1)  ; r0 += r1"
  [dst src]
  (alu-reg :add dst src))

(defn sub
  "Subtract immediate from register (64-bit).

  Example:
    (sub :r0 10)  ; r0 -= 10"
  [dst imm]
  (alu-imm :sub dst imm))

(defn sub-reg
  "Subtract register from register (64-bit).

  Example:
    (sub-reg :r0 :r1)  ; r0 -= r1"
  [dst src]
  (alu-reg :sub dst src))

(defn mul
  "Multiply register by immediate (64-bit).

  Example:
    (mul :r0 2)  ; r0 *= 2"
  [dst imm]
  (alu-imm :mul dst imm))

(defn mul-reg
  "Multiply register by register (64-bit).

  Example:
    (mul-reg :r0 :r1)  ; r0 *= r1"
  [dst src]
  (alu-reg :mul dst src))

(defn div
  "Divide register by immediate (64-bit).

  Example:
    (div :r0 2)  ; r0 /= 2"
  [dst imm]
  (alu-imm :div dst imm))

(defn div-reg
  "Divide register by register (64-bit).

  Example:
    (div-reg :r0 :r1)  ; r0 /= r1"
  [dst src]
  (alu-reg :div dst src))

(defn mod
  "Modulo register by immediate (64-bit).

  Example:
    (mod :r0 10)  ; r0 %= 10"
  [dst imm]
  (alu-imm :mod dst imm))

(defn mod-reg
  "Modulo register by register (64-bit).

  Example:
    (mod-reg :r0 :r1)  ; r0 %= r1"
  [dst src]
  (alu-reg :mod dst src))

(defn and-op
  "Bitwise AND with immediate (64-bit).

  Example:
    (and-op :r0 0xFF)  ; r0 &= 0xFF"
  [dst imm]
  (alu-imm :and dst imm))

(defn and-reg
  "Bitwise AND with register (64-bit).

  Example:
    (and-reg :r0 :r1)  ; r0 &= r1"
  [dst src]
  (alu-reg :and dst src))

(defn or-op
  "Bitwise OR with immediate (64-bit).

  Example:
    (or-op :r0 0x10)  ; r0 |= 0x10"
  [dst imm]
  (alu-imm :or dst imm))

(defn or-reg
  "Bitwise OR with register (64-bit).

  Example:
    (or-reg :r0 :r1)  ; r0 |= r1"
  [dst src]
  (alu-reg :or dst src))

(defn xor-op
  "Bitwise XOR with immediate (64-bit).

  Example:
    (xor-op :r0 0xFF)  ; r0 ^= 0xFF"
  [dst imm]
  (alu-imm :xor dst imm))

(defn xor-reg
  "Bitwise XOR with register (64-bit).

  Example:
    (xor-reg :r0 :r1)  ; r0 ^= r1"
  [dst src]
  (alu-reg :xor dst src))

(defn lsh
  "Left shift by immediate (64-bit).

  Example:
    (lsh :r0 8)  ; r0 <<= 8"
  [dst imm]
  (alu-imm :lsh dst imm))

(defn lsh-reg
  "Left shift by register (64-bit).

  Example:
    (lsh-reg :r0 :r1)  ; r0 <<= r1"
  [dst src]
  (alu-reg :lsh dst src))

(defn rsh
  "Right shift (logical) by immediate (64-bit).

  Example:
    (rsh :r0 8)  ; r0 >>= 8"
  [dst imm]
  (alu-imm :rsh dst imm))

(defn rsh-reg
  "Right shift (logical) by register (64-bit).

  Example:
    (rsh-reg :r0 :r1)  ; r0 >>= r1"
  [dst src]
  (alu-reg :rsh dst src))

(defn arsh
  "Arithmetic right shift by immediate (64-bit).

  Example:
    (arsh :r0 8)  ; r0 = (s64)r0 >> 8"
  [dst imm]
  (alu-imm :arsh dst imm))

(defn neg-reg
  "Negate register (64-bit).

  Example:
    (neg-reg :r0)  ; r0 = -r0"
  [dst]
  (alu-imm :neg dst 0))

(defn end-to-be
  "Convert register from host byte order to big-endian (network byte order).

  size: Bit size - 16, 32, or 64

  Example:
    (end-to-be :r0 16)  ; r0 = htobe16(r0)
    (end-to-be :r1 32)  ; r1 = htobe32(r1)"
  [dst size]
  (let [opcode (bit-or (get alu-op :end)
                      (get instruction-class :alu))]
    (build-instruction opcode (resolve-register dst) 0 0 size)))

(defn end-to-le
  "Convert register from host byte order to little-endian.

  size: Bit size - 16, 32, or 64

  Note: On x86/x86_64 (little-endian), this is essentially a no-op.
  The instruction is provided for portability.

  Example:
    (end-to-le :r0 16)  ; r0 = htole16(r0)
    (end-to-le :r1 32)  ; r1 = htole32(r1)"
  [dst size]
  (let [opcode (bit-or (get alu-op :end)
                      (get instruction-class :alu)
                      0x08)]  ; BPF_TO_LE flag
    (build-instruction opcode (resolve-register dst) 0 0 size)))

;; ============================================================================
;; Jump Instructions
;; ============================================================================

(defn jmp-imm
  "Jump if condition with immediate operand.

  Example:
    (jmp-imm :jeq :r0 0 label-offset)  ; if r0 == 0 goto +offset"
  [op dst imm offset]
  (let [opcode (bit-or (get jmp-op op)
                      (get source-operand :k)
                      (get instruction-class :jmp))
        dst-reg (resolve-register dst)]
    (build-instruction opcode dst-reg 0 offset imm)))

(defn jmp-reg
  "Jump if condition with register operand.

  Example:
    (jmp-reg :jeq :r0 :r1 label-offset)  ; if r0 == r1 goto +offset"
  [op dst src offset]
  (let [opcode (bit-or (get jmp-op op)
                      (get source-operand :x)
                      (get instruction-class :jmp))
        dst-reg (resolve-register dst)
        src-reg (resolve-register src)]
    (build-instruction opcode dst-reg src-reg offset 0)))

(defn ja
  "Unconditional jump.

  Example:
    (ja label-offset)  ; goto +offset"
  [offset]
  (let [opcode (bit-or (get jmp-op :ja)
                      (get instruction-class :jmp))]
    (build-instruction opcode 0 0 offset 0)))

(defn call
  "Call BPF helper function.

  Example:
    (call (:map-lookup-elem bpf-helpers))  ; call helper"
  [helper-id]
  (let [opcode (bit-or (get jmp-op :call)
                      (get instruction-class :jmp))]
    (build-instruction opcode 0 0 0 helper-id)))

(defn exit-insn
  "Exit BPF program.

  Example:
    (exit-insn)  ; return"
  []
  (let [opcode (bit-or (get jmp-op :exit)
                      (get instruction-class :jmp))]
    (build-instruction opcode 0 0 0 0)))

;; ============================================================================
;; Load/Store Instructions
;; ============================================================================

(defn ldx
  "Load from memory into register.

  Example:
    (ldx :dw :r0 :r1 4)  ; r0 = *(u64*)(r1 + 4)"
  [size dst src offset]
  (let [opcode (bit-or (get load-store-size size)
                      (get load-store-mode :mem)
                      (get instruction-class :ldx))
        dst-reg (resolve-register dst)
        src-reg (resolve-register src)]
    (build-instruction opcode dst-reg src-reg offset 0)))

(defn stx
  "Store register to memory.

  Example:
    (stx :dw :r1 :r0 4)  ; *(u64*)(r1 + 4) = r0"
  [size dst src offset]
  (let [opcode (bit-or (get load-store-size size)
                      (get load-store-mode :mem)
                      (get instruction-class :stx))
        dst-reg (resolve-register dst)
        src-reg (resolve-register src)]
    (build-instruction opcode dst-reg src-reg offset 0)))

(defn st
  "Store immediate to memory.

  Example:
    (st :dw :r1 4 42)  ; *(u64*)(r1 + 4) = 42"
  [size dst offset imm]
  (let [opcode (bit-or (get load-store-size size)
                      (get load-store-mode :mem)
                      (get instruction-class :st))
        dst-reg (resolve-register dst)]
    (build-instruction opcode dst-reg 0 offset imm)))

;; ============================================================================
;; Wide (128-bit) Instructions
;; ============================================================================

(defn lddw
  "Load 64-bit immediate (wide instruction).

  Example:
    (lddw :r0 0x123456789ABCDEF)  ; r0 = 0x123456789ABCDEF"
  [dst imm64]
  (let [opcode (bit-or (get load-store-size :dw)
                      (get load-store-mode :imm)
                      (get instruction-class :ld))
        dst-reg (resolve-register dst)
        imm-lo (unchecked-int (bit-and imm64 0xFFFFFFFF))
        imm-hi (unchecked-int (bit-and (unsigned-bit-shift-right imm64 32) 0xFFFFFFFF))
        insn1 (build-instruction opcode dst-reg 0 0 imm-lo)
        insn2 (build-instruction 0 0 0 0 imm-hi)]
    (byte-array (concat insn1 insn2))))

;; ============================================================================
;; Program Assembly
;; ============================================================================

(defn assemble
  "Assemble a sequence of instructions into BPF bytecode.

  Parameters:
  - instructions: Sequence of instruction byte arrays

  Returns combined byte array.

  Example:
    (assemble [(mov :r0 0)
               (exit-insn)])"
  [instructions]
  (byte-array (apply concat instructions)))

;; ============================================================================
;; High-Level DSL Macros
;; ============================================================================

(defmacro defbpf
  "Define a BPF program using DSL.

  Example:
    (defbpf my-program
      (mov :r0 0)
      (exit-insn))"
  [name & body]
  `(def ~name
     (assemble [~@body])))

(defn compile-program
  "Compile DSL instructions into BPF bytecode at runtime.

  Parameters:
  - instructions: List of DSL instruction forms

  Returns byte array.

  Example:
    (compile-program
      (mov :r0 2)
      (exit-insn))"
  [& instructions]
  (assemble instructions))
