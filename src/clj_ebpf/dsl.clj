(ns clj-ebpf.dsl
  "Idiomatic Clojure DSL for BPF programming"
  (:require [clj-ebpf.arch :as arch]
            [clj-ebpf.btf :as btf]
            [clj-ebpf.utils :as utils]))

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
   :setsockopt             49
   :skb-adjust-room        50
   :redirect-map           51
   :sk-redirect-map        52
   :sock-map-update        53
   :xdp-adjust-meta        54
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
;; Tutorial-Compatible Aliases
;; ============================================================================
;; These functions provide alternative signatures that match tutorial examples

(defn load-mem
  "Load from memory into register (tutorial-compatible alias for ldx).

  Example:
    (load-mem :dw :r0 :r1 4)  ; r0 = *(u64*)(r1 + 4)"
  [size dst src offset]
  (ldx size dst src offset))

(defn store-mem
  "Store register to memory (tutorial-compatible alias).
  Note: Uses [size dst offset src] order for readability.

  Example:
    (store-mem :dw :r10 -8 :r6)  ; *(u64*)(r10 - 8) = r6"
  [size dst offset src]
  (stx size dst src offset))

(defn ld-map-fd
  "Load map file descriptor into register (tutorial-compatible).
  Uses lddw with BPF_PSEUDO_MAP_FD source register marker.

  Example:
    (ld-map-fd :r1 map-fd)  ; r1 = map_fd (for helper calls)"
  [dst map-fd]
  ;; BPF_PSEUDO_MAP_FD = 1, used as src register to indicate map fd
  (let [opcode (bit-or (get load-store-size :dw)
                       (get load-store-mode :imm)
                       (get instruction-class :ld))
        dst-reg (resolve-register dst)
        ;; Split map-fd into low and high 32 bits
        imm-lo (unchecked-int (bit-and map-fd 0xFFFFFFFF))
        imm-hi 0  ; Map FDs fit in 32 bits
        ;; src=1 indicates BPF_PSEUDO_MAP_FD
        insn1 (build-instruction opcode dst-reg 1 0 imm-lo)
        insn2 (build-instruction 0 0 0 0 imm-hi)]
    (byte-array (concat insn1 insn2))))

(defn jmp
  "Unconditional jump (tutorial-compatible alias for ja).
  Note: offset is in instructions, not bytes.

  Example:
    (jmp 5)  ; Jump forward 5 instructions"
  [offset]
  (ja offset))

(defn exit
  "Exit program (tutorial-compatible alias for exit-insn)."
  []
  (exit-insn))

(defn load-ctx
  "Load from context pointer (alias for ldx with r1 as source).
  Commonly used to read fields from BPF program context.

  Example:
    (load-ctx :dw :r2 0)  ; r2 = *(u64*)(ctx + 0)"
  [size dst offset]
  (ldx size dst :r1 offset))

(defn map-ref
  "Reference to a map for use in instructions.
  Returns the map-fd for use with ld-map-fd.

  Example:
    (ld-map-fd :r1 (map-ref my-map))"
  [map-or-fd]
  (if (map? map-or-fd)
    (:fd map-or-fd)
    map-or-fd))

;; 'and' function for tutorial compatibility
;; Note: This shadows clojure.core/and but tutorials expect bpf/and to work
(defn and
  "Bitwise AND operation (tutorial-compatible).
  Handles both immediate and register sources.

  Example:
    (and :r0 0xFF)     ; r0 &= 0xFF (immediate)
    (and :r0 :r1)      ; r0 &= r1 (register)"
  [dst src-or-imm]
  (if (keyword? src-or-imm)
    (and-reg dst src-or-imm)
    (and-op dst src-or-imm)))

(defn endian-be
  "Convert to big-endian (tutorial-compatible alias for end-to-be).

  Example:
    (endian-be :h :r5)  ; Convert r5 to big-endian 16-bit"
  [size dst]
  (end-to-be size dst))

(defn endian-le
  "Convert to little-endian (tutorial-compatible alias for end-to-le).

  Example:
    (endian-le :w :r5)  ; Convert r5 to little-endian 32-bit"
  [size dst]
  (end-to-le size dst))

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

;;; =============================================================================
;;; CO-RE (Compile Once - Run Everywhere) Helpers
;;; =============================================================================

(defn core-field-offset
  "Generate placeholder instruction for CO-RE field offset relocation.

  This generates a MOV instruction with a placeholder immediate value (0)
  that will be relocated at load time using BTF information to the correct
  field offset.

  Note: Actual CO-RE relocation requires BTF data and relocation records
  that are typically handled by the ELF loader or program loader.

  Parameters:
  - dst: Destination register
  - struct-name: Structure name (for documentation/debugging)
  - field-name: Field name (for documentation/debugging)

  Returns instruction byte array with placeholder offset.

  Example:
    ;; Load offset of task_struct->pid into r1
    (core-field-offset :r1 \"task_struct\" \"pid\")

  The placeholder value (0) would be replaced with the actual offset
  during program loading when CO-RE relocations are processed."
  [dst struct-name field-name]
  ;; Generate MOV instruction with 0 immediate - will be relocated
  (mov dst 0))

(defn core-field-exists
  "Generate placeholder instruction for CO-RE field existence check.

  Returns 1 if field exists in target kernel, 0 if not.

  Parameters:
  - dst: Destination register
  - struct-name: Structure name
  - field-name: Field name

  Returns instruction byte array.

  Example:
    ;; Check if task_struct has 'pids' field
    (core-field-exists :r0 \"task_struct\" \"pids\")"
  [dst struct-name field-name]
  ;; Generate MOV instruction with 0 - will be relocated to 0 or 1
  (mov dst 0))

(defn core-field-size
  "Generate placeholder instruction for CO-RE field size relocation.

  Returns size of field in bytes.

  Parameters:
  - dst: Destination register
  - struct-name: Structure name
  - field-name: Field name

  Returns instruction byte array.

  Example:
    ;; Get size of task_struct->comm field
    (core-field-size :r1 \"task_struct\" \"comm\")"
  [dst struct-name field-name]
  ;; Generate MOV instruction with 0 - will be relocated to actual size
  (mov dst 0))

(defn core-type-exists
  "Generate placeholder instruction for CO-RE type existence check.

  Returns 1 if type exists in target kernel, 0 if not.

  Parameters:
  - dst: Destination register
  - type-name: Type name to check

  Returns instruction byte array.

  Example:
    ;; Check if 'struct bpf_map' exists
    (core-type-exists :r0 \"struct bpf_map\")"
  [dst type-name]
  ;; Generate MOV instruction with 0 - will be relocated to 0 or 1
  (mov dst 0))

(defn core-type-size
  "Generate placeholder instruction for CO-RE type size relocation.

  Returns size of type in bytes.

  Parameters:
  - dst: Destination register
  - type-name: Type name

  Returns instruction byte array.

  Example:
    ;; Get size of task_struct
    (core-type-size :r1 \"task_struct\")"
  [dst type-name]
  ;; Generate MOV instruction with 0 - will be relocated to actual size
  (mov dst 0))

(defn core-enum-value
  "Generate placeholder instruction for CO-RE enum value relocation.

  Returns the integer value of an enum constant.

  Parameters:
  - dst: Destination register
  - enum-name: Enum type name
  - value-name: Enum value name

  Returns instruction byte array.

  Example:
    ;; Get value of TASK_RUNNING from task state enum
    (core-enum-value :r0 \"task_state\" \"TASK_RUNNING\")"
  [dst enum-name value-name]
  ;; Generate MOV instruction with 0 - will be relocated to actual value
  (mov dst 0))

(comment
  "CO-RE Helper Usage Examples"

  ;; Example 1: Read task PID with CO-RE
  (assemble [;; r1 = current task pointer (from r1 context)
             ;; Get offset of 'pid' field
             (core-field-offset :r2 "task_struct" "pid")
             ;; Add offset to task pointer: r1 = r1 + r2
             (add-reg :r1 :r2)
             ;; Load PID value: r0 = *(r1 + 0)
             (ldx :w :r0 :r1 0)
             (exit-insn)])

  ;; Example 2: Conditional code based on field existence
  (assemble [;; Check if new field exists
             (core-field-exists :r0 "task_struct" "new_field")
             ;; if r0 == 0 (field doesn't exist), skip new code
             (jmp-imm :jeq :r0 0 2)
             ;; New field exists - use it
             (core-field-offset :r1 "task_struct" "new_field")
             (ja 1)  ; Jump over old code
             ;; Old field fallback
             (core-field-offset :r1 "task_struct" "old_field")
             ;; Continue with program
             (exit-insn)])

  ;; Example 3: Allocate buffer based on structure size
  (assemble [;; Get size of structure
             (core-type-size :r1 "task_struct")
             ;; Allocate on stack: r10 = r10 - r1
             (sub-reg :r10 :r1)
             (exit-insn)]))

(defn generate-core-read
  "Generate BPF CO-RE read sequence for nested field access.

  This generates a sequence of instructions to safely read a field from
  a structure with CO-RE relocations, including NULL pointer checks.

  Pattern similar to BPF_CORE_READ macro in C.

  Parameters:
  - dst: Destination register for the result
  - src: Source register containing pointer to structure
  - field-spec: Map with :struct-name and :field-name

  Returns sequence of instruction byte arrays.

  Example:
    ;; Read current->pid
    (generate-core-read :r0 :r1
      {:struct-name \"task_struct\"
       :field-name \"pid\"})"
  [dst src field-spec]
  (let [{:keys [struct-name field-name]} field-spec]
    [;; Save source pointer
     (mov-reg :r6 src)
     ;; Get field offset
     (core-field-offset :r7 struct-name field-name)
     ;; Add offset to pointer: r6 = r6 + r7
     (add-reg :r6 :r7)
     ;; Load value: dst = *(r6 + 0)
     ;; Size determined by field type (using :w for 32-bit as example)
     (ldx :w dst :r6 0)]))

;; ============================================================================
;; BPF Helper Function Wrappers
;; ============================================================================
;;
;; These functions provide high-level wrappers around BPF helper functions.
;; Each wrapper sets up the required registers according to the BPF calling
;; convention and generates the helper call instruction.
;;
;; BPF Calling Convention:
;; - r1-r5: Function arguments
;; - r0: Return value
;; - r6-r9: Callee-saved registers (preserved across calls)
;; - r10: Read-only frame pointer

;; === Map Helpers ===

(defn helper-map-lookup-elem
  "Call bpf_map_lookup_elem helper.

  Look up an element in a BPF map by key.

  Parameters:
  - map-reg: Register containing map file descriptor (or direct FD value)
  - key-reg: Register containing pointer to key

  Returns pointer to value in r0, or NULL if not found.

  Example:
    (helper-map-lookup-elem :r1 :r2)
    ;; r0 will contain pointer to value or NULL"
  [map-reg key-reg]
  [(mov-reg :r1 map-reg)
   (mov-reg :r2 key-reg)
   (call 1)])  ; bpf_map_lookup_elem = 1

(defn helper-map-update-elem
  "Call bpf_map_update_elem helper.

  Update or insert an element in a BPF map.

  Parameters:
  - map-reg: Register containing map file descriptor
  - key-reg: Register containing pointer to key
  - value-reg: Register containing pointer to value
  - flags-reg: Register containing flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST)

  Returns 0 on success, negative error code on failure.

  Example:
    (helper-map-update-elem :r1 :r2 :r3 :r4)
    ;; r0 = 0 on success, < 0 on error"
  [map-reg key-reg value-reg flags-reg]
  [(mov-reg :r1 map-reg)
   (mov-reg :r2 key-reg)
   (mov-reg :r3 value-reg)
   (mov-reg :r4 flags-reg)
   (call 2)])  ; bpf_map_update_elem = 2

(defn helper-map-delete-elem
  "Call bpf_map_delete_elem helper.

  Delete an element from a BPF map.

  Parameters:
  - map-reg: Register containing map file descriptor
  - key-reg: Register containing pointer to key

  Returns 0 on success, negative error code on failure.

  Example:
    (helper-map-delete-elem :r1 :r2)
    ;; r0 = 0 on success, < 0 on error"
  [map-reg key-reg]
  [(mov-reg :r1 map-reg)
   (mov-reg :r2 key-reg)
   (call 3)])  ; bpf_map_delete_elem = 3

;; === Probe/Trace Helpers ===

(defn helper-probe-read
  "Call bpf_probe_read helper.

  Read memory from an unsafe pointer (kernel or user).

  Parameters:
  - dst-reg: Register containing destination buffer pointer
  - size-reg: Register containing size to read
  - src-reg: Register containing unsafe source pointer

  Returns 0 on success, negative error code on failure.

  Example:
    (helper-probe-read :r1 :r2 :r3)
    ;; Reads r2 bytes from r3 to r1"
  [dst-reg size-reg src-reg]
  [(mov-reg :r1 dst-reg)
   (mov-reg :r2 size-reg)
   (mov-reg :r3 src-reg)
   (call 4)])  ; bpf_probe_read = 4

(defn helper-probe-read-kernel
  "Call bpf_probe_read_kernel helper.

  Read memory from kernel space pointer.

  Parameters:
  - dst-reg: Register containing destination buffer pointer
  - size-reg: Register containing size to read
  - src-reg: Register containing kernel pointer

  Returns 0 on success, negative error code on failure.

  Example:
    (helper-probe-read-kernel :r1 :r2 :r3)"
  [dst-reg size-reg src-reg]
  [(mov-reg :r1 dst-reg)
   (mov-reg :r2 size-reg)
   (mov-reg :r3 src-reg)
   (call 113)])  ; bpf_probe_read_kernel = 113

(defn helper-probe-read-user
  "Call bpf_probe_read_user helper.

  Read memory from user space pointer.

  Parameters:
  - dst-reg: Register containing destination buffer pointer
  - size-reg: Register containing size to read
  - src-reg: Register containing user pointer

  Returns 0 on success, negative error code on failure.

  Example:
    (helper-probe-read-user :r1 :r2 :r3)"
  [dst-reg size-reg src-reg]
  [(mov-reg :r1 dst-reg)
   (mov-reg :r2 size-reg)
   (mov-reg :r3 src-reg)
   (call 112)])  ; bpf_probe_read_user = 112

(defn helper-probe-read-str
  "Call bpf_probe_read_str helper.

  Read null-terminated string from unsafe pointer.

  Parameters:
  - dst-reg: Register containing destination buffer pointer
  - size-reg: Register containing max size to read
  - src-reg: Register containing unsafe source pointer

  Returns length of string (including NULL) on success, negative on error.

  Example:
    (helper-probe-read-str :r1 :r2 :r3)"
  [dst-reg size-reg src-reg]
  [(mov-reg :r1 dst-reg)
   (mov-reg :r2 size-reg)
   (mov-reg :r3 src-reg)
   (call 45)])  ; bpf_probe_read_str = 45

(defn helper-probe-read-kernel-str
  "Call bpf_probe_read_kernel_str helper.

  Read null-terminated string from kernel pointer.

  Parameters:
  - dst-reg: Register containing destination buffer pointer
  - size-reg: Register containing max size to read
  - src-reg: Register containing kernel pointer

  Returns length of string (including NULL) on success, negative on error."
  [dst-reg size-reg src-reg]
  [(mov-reg :r1 dst-reg)
   (mov-reg :r2 size-reg)
   (mov-reg :r3 src-reg)
   (call 115)])  ; bpf_probe_read_kernel_str = 115

(defn helper-probe-read-user-str
  "Call bpf_probe_read_user_str helper.

  Read null-terminated string from user pointer.

  Parameters:
  - dst-reg: Register containing destination buffer pointer
  - size-reg: Register containing max size to read
  - src-reg: Register containing user pointer

  Returns length of string (including NULL) on success, negative on error."
  [dst-reg size-reg src-reg]
  [(mov-reg :r1 dst-reg)
   (mov-reg :r2 size-reg)
   (mov-reg :r3 src-reg)
   (call 114)])  ; bpf_probe_read_user_str = 114

(defn read-kprobe-arg
  "Read a kprobe function argument from the pt_regs context.

  In kprobe programs, r1 contains a pointer to the pt_regs structure
  which holds the CPU registers at the time of the probe. This function
  generates instructions to read argument N from pt_regs into a destination
  register.

  The pt_regs offsets are architecture-specific and are automatically
  determined based on the current runtime architecture.

  Parameters:
  - ctx-reg: Register containing pt_regs pointer (typically :r1 at kprobe entry)
  - arg-index: Argument index (0 = first argument, 1 = second, etc.)
  - dst-reg: Destination register to store the argument value

  Returns a single ldx instruction.

  Example:
    ;; At kprobe entry, r1 = pt_regs*
    (read-kprobe-arg :r1 0 :r6)  ; r6 = first function argument (sk pointer)
    (read-kprobe-arg :r1 1 :r7)  ; r7 = second function argument

  Architecture support:
  - x86_64:  Arguments in rdi, rsi, rdx, rcx, r8, r9
  - arm64:   Arguments in x0-x7
  - s390x:   Arguments in r2-r6
  - ppc64le: Arguments in r3-r10
  - riscv64: Arguments in a0-a7"
  [ctx-reg arg-index dst-reg]
  (let [offset (arch/get-kprobe-arg-offset arg-index)]
    (ldx :dw dst-reg ctx-reg offset)))

(defn core-read
  "Generate CO-RE relocatable field read instructions.

  Reads a field from a kernel structure using BTF information for
  CO-RE (Compile Once - Run Everywhere) compatibility. The field offset
  is determined at load time based on the target kernel's BTF.

  Parameters:
  - btf-data: BTF data from btf/load-btf-file
  - dst-reg: Destination register for the read value
  - src-reg: Source register containing struct pointer
  - struct-name: Name of the kernel struct (string)
  - field-path: Vector of field names to traverse, e.g., [:__sk_common :skc_daddr]

  Returns instruction sequence for reading the field value.
  Uses bpf_probe_read_kernel for safe kernel memory access.

  Example:
    ;; Read sk->__sk_common.skc_daddr into r6
    (core-read btf :r6 :r7 \"sock\" [:__sk_common :skc_daddr])

  Note: This generates a compile-time resolved offset. For true CO-RE
  relocation at load time, use the relocate namespace functions."
  [btf-data dst-reg src-reg struct-name field-path]
  (let [type-info (btf/find-type-by-name btf-data struct-name)
        _ (when-not type-info
            (throw (ex-info (str "Struct not found in BTF: " struct-name)
                           {:struct struct-name :field-path field-path})))
        access-info (btf/field-path->access-info btf-data (:id type-info) field-path)
        _ (when-not access-info
            (throw (ex-info (str "Field path not found: " field-path)
                           {:struct struct-name :field-path field-path})))
        offset (:byte-offset access-info)
        _ (when-not offset
            (throw (ex-info "Field is not byte-aligned"
                           {:struct struct-name :field-path field-path
                            :bit-offset (:bit-offset access-info)})))
        field-type-id (:final-type-id access-info)
        field-size (btf/get-type-size btf-data field-type-id)
        size-keyword (case field-size
                       1 :b
                       2 :h
                       4 :w
                       8 :dw
                       :dw)]  ; Default to dword for pointers, etc.
    ;; Generate load instruction with computed offset
    (ldx size-keyword dst-reg src-reg offset)))

(defn core-read-safe
  "Generate CO-RE field read using bpf_probe_read_kernel for safety.

  Like core-read but uses bpf_probe_read_kernel helper instead of
  direct memory load. This is safer for potentially invalid pointers.

  The result is stored on the stack at the given offset, then loaded
  into the destination register.

  Parameters:
  - btf-data: BTF data from btf/load-btf-file
  - dst-reg: Destination register for the read value
  - src-reg: Source register containing struct pointer
  - struct-name: Name of the kernel struct (string)
  - field-path: Vector of field names to traverse
  - stack-offset: Stack offset for temporary storage (negative, e.g., -8)

  Returns instruction sequence.

  Example:
    ;; Safely read sk->__sk_common.skc_daddr
    (core-read-safe btf :r6 :r7 \"sock\" [:__sk_common :skc_daddr] -8)"
  [btf-data dst-reg src-reg struct-name field-path stack-offset]
  (let [type-info (btf/find-type-by-name btf-data struct-name)
        _ (when-not type-info
            (throw (ex-info (str "Struct not found in BTF: " struct-name)
                           {:struct struct-name})))
        access-info (btf/field-path->access-info btf-data (:id type-info) field-path)
        _ (when-not access-info
            (throw (ex-info (str "Field path not found: " field-path)
                           {:struct struct-name :field-path field-path})))
        offset (:byte-offset access-info)
        field-type-id (:final-type-id access-info)
        field-size (or (btf/get-type-size btf-data field-type-id) 8)]
    (vec (concat
          ;; r1 = destination (stack pointer + offset)
          [(mov-reg :r1 :r10)]
          [(add :r1 stack-offset)]
          ;; r2 = size to read
          [(mov :r2 field-size)]
          ;; r3 = source pointer + field offset
          [(mov-reg :r3 src-reg)]
          [(add :r3 offset)]
          ;; Call bpf_probe_read_kernel
          [(call 113)]  ; bpf_probe_read_kernel = 113
          ;; Load result from stack into destination register
          [(ldx :dw dst-reg :r10 stack-offset)]))))

;; === Time Helpers ===

(defn helper-ktime-get-ns
  "Call bpf_ktime_get_ns helper.

  Get monotonic time in nanoseconds since system boot.

  Returns nanosecond timestamp in r0.

  Example:
    (helper-ktime-get-ns)
    ;; r0 = timestamp in nanoseconds"
  []
  [(call 5)])  ; bpf_ktime_get_ns = 5

(defn helper-ktime-get-boot-ns
  "Call bpf_ktime_get_boot_ns helper.

  Get monotonic time in nanoseconds including suspend time.

  Returns nanosecond timestamp in r0.

  Example:
    (helper-ktime-get-boot-ns)
    ;; r0 = timestamp including suspend"
  []
  [(call 125)])  ; bpf_ktime_get_boot_ns = 125

(defn helper-jiffies64
  "Call bpf_jiffies64 helper.

  Get current jiffies64 value.

  Returns jiffies64 value in r0."
  []
  [(call 118)])  ; bpf_jiffies64 = 118

(defn helper-ktime-get-coarse-ns
  "Call bpf_ktime_get_coarse_ns helper.

  Get coarse-grained monotonic time (faster but less precise).

  Returns nanosecond timestamp in r0."
  []
  [(call 190)])  ; bpf_ktime_get_coarse_ns = 190

(defn helper-ktime-get-tai-ns
  "Call bpf_ktime_get_tai_ns helper.

  Get TAI (International Atomic Time) in nanoseconds.

  Returns TAI timestamp in r0."
  []
  [(call 208)])  ; bpf_ktime_get_tai_ns = 208

;; === Process Information Helpers ===

(defn helper-get-current-pid-tgid
  "Call bpf_get_current_pid_tgid helper.

  Get current process PID and thread group ID.

  Returns u64 in r0 where:
  - Upper 32 bits = TGID (process ID)
  - Lower 32 bits = PID (thread ID)

  Example:
    (helper-get-current-pid-tgid)
    ;; r0 = (tgid << 32) | pid"
  []
  [(call 14)])  ; bpf_get_current_pid_tgid = 14

(defn helper-get-current-uid-gid
  "Call bpf_get_current_uid_gid helper.

  Get current process UID and GID.

  Returns u64 in r0 where:
  - Upper 32 bits = GID
  - Lower 32 bits = UID

  Example:
    (helper-get-current-uid-gid)
    ;; r0 = (gid << 32) | uid"
  []
  [(call 15)])  ; bpf_get_current_uid_gid = 15

(defn helper-get-current-comm
  "Call bpf_get_current_comm helper.

  Get current process command name.

  Parameters:
  - buf-reg: Register containing pointer to buffer (min 16 bytes)
  - size-reg: Register containing buffer size

  Returns 0 on success, negative on error.

  Example:
    (helper-get-current-comm :r1 :r2)
    ;; Fills buffer at r1 with command name"
  [buf-reg size-reg]
  [(mov-reg :r1 buf-reg)
   (mov-reg :r2 size-reg)
   (call 16)])  ; bpf_get_current_comm = 16

(defn helper-get-current-task
  "Call bpf_get_current_task helper.

  Get pointer to current task_struct.

  Returns pointer to task_struct in r0.

  Example:
    (helper-get-current-task)
    ;; r0 = pointer to current task_struct"
  []
  [(call 35)])  ; bpf_get_current_task = 35

(defn helper-get-current-task-btf
  "Call bpf_get_current_task_btf helper.

  Get pointer to current task_struct with BTF type info.

  Returns BTF pointer to task_struct in r0."
  []
  [(call 188)])  ; bpf_get_current_task_btf = 188

;; === CPU/System Information Helpers ===

(defn helper-get-smp-processor-id
  "Call bpf_get_smp_processor_id helper.

  Get current CPU number.

  Returns CPU ID in r0.

  Example:
    (helper-get-smp-processor-id)
    ;; r0 = current CPU number"
  []
  [(call 8)])  ; bpf_get_smp_processor_id = 8

(defn helper-get-numa-node-id
  "Call bpf_get_numa_node_id helper.

  Get current NUMA node ID.

  Returns NUMA node ID in r0."
  []
  [(call 42)])  ; bpf_get_numa_node-id = 42

(defn helper-get-prandom-u32
  "Call bpf_get_prandom_u32 helper.

  Get pseudo-random 32-bit number.

  Returns random u32 in r0.

  Example:
    (helper-get-prandom-u32)
    ;; r0 = random number"
  []
  [(call 7)])  ; bpf_get_prandom_u32 = 7

;; === Stack Trace Helpers ===

(defn helper-get-stackid
  "Call bpf_get_stackid helper.

  Get stack trace ID for current context.

  Parameters:
  - ctx-reg: Register containing context pointer
  - map-reg: Register containing stack trace map FD
  - flags-reg: Register containing flags

  Returns stack ID in r0 (>= 0), or negative on error.

  Example:
    (helper-get-stackid :r1 :r2 :r3)"
  [ctx-reg map-reg flags-reg]
  [(mov-reg :r1 ctx-reg)
   (mov-reg :r2 map-reg)
   (mov-reg :r3 flags-reg)
   (call 27)])  ; bpf_get_stackid = 27

(defn helper-get-stack
  "Call bpf_get_stack helper.

  Get kernel or user stack trace.

  Parameters:
  - ctx-reg: Register containing context pointer
  - buf-reg: Register containing buffer pointer
  - size-reg: Register containing buffer size
  - flags-reg: Register containing flags (kernel/user, skip frames, etc.)

  Returns number of bytes written, or negative on error.

  Example:
    (helper-get-stack :r1 :r2 :r3 :r4)"
  [ctx-reg buf-reg size-reg flags-reg]
  [(mov-reg :r1 ctx-reg)
   (mov-reg :r2 buf-reg)
   (mov-reg :r3 size-reg)
   (mov-reg :r4 flags-reg)
   (call 67)])  ; bpf_get_stack = 67

(defn helper-get-task-stack
  "Call bpf_get_task_stack helper.

  Get stack trace for a specific task.

  Parameters:
  - task-reg: Register containing task_struct pointer
  - buf-reg: Register containing buffer pointer
  - size-reg: Register containing buffer size
  - flags-reg: Register containing flags

  Returns number of bytes written, or negative on error."
  [task-reg buf-reg size-reg flags-reg]
  [(mov-reg :r1 task-reg)
   (mov-reg :r2 buf-reg)
   (mov-reg :r3 size-reg)
   (mov-reg :r4 flags-reg)
   (call 141)])  ; bpf_get_task_stack = 141

;; === Perf Event Helpers ===

(defn helper-perf-event-output
  "Call bpf_perf_event_output helper.

  Write data to perf event buffer.

  Parameters:
  - ctx-reg: Register containing context pointer
  - map-reg: Register containing perf event map FD
  - flags-reg: Register containing flags (usually CPU number)
  - data-reg: Register containing data pointer
  - size-reg: Register containing data size

  Returns 0 on success, negative on error.

  Example:
    (helper-perf-event-output :r1 :r2 :r3 :r4 :r5)"
  [ctx-reg map-reg flags-reg data-reg size-reg]
  [(mov-reg :r1 ctx-reg)
   (mov-reg :r2 map-reg)
   (mov-reg :r3 flags-reg)
   (mov-reg :r4 data-reg)
   (mov-reg :r5 size-reg)
   (call 25)])  ; bpf_perf_event_output = 25

(defn helper-perf-event-read
  "Call bpf_perf_event_read helper.

  Read perf event counter value.

  Parameters:
  - map-reg: Register containing perf event array map FD
  - flags-reg: Register containing flags/index

  Returns counter value in r0.

  Example:
    (helper-perf-event-read :r1 :r2)"
  [map-reg flags-reg]
  [(mov-reg :r1 map-reg)
   (mov-reg :r2 flags-reg)
   (call 22)])  ; bpf_perf_event_read = 22

;; === Ring Buffer Helpers ===

(defn helper-ringbuf-output
  "Call bpf_ringbuf_output helper.

  Write data to ring buffer (simplified interface).

  Parameters:
  - ringbuf-reg: Register containing ring buffer map FD
  - data-reg: Register containing data pointer
  - size-reg: Register containing data size
  - flags-reg: Register containing flags

  Returns 0 on success, negative on error.

  Example:
    (helper-ringbuf-output :r1 :r2 :r3 :r4)"
  [ringbuf-reg data-reg size-reg flags-reg]
  [(mov-reg :r1 ringbuf-reg)
   (mov-reg :r2 data-reg)
   (mov-reg :r3 size-reg)
   (mov-reg :r4 flags-reg)
   (call 130)])  ; bpf_ringbuf_output = 130

(defn helper-ringbuf-reserve
  "Call bpf_ringbuf_reserve helper.

  Reserve space in ring buffer for writing.

  Parameters:
  - ringbuf-reg: Register containing ring buffer map FD
  - size-reg: Register containing size to reserve
  - flags-reg: Register containing flags

  Returns pointer to reserved space in r0, or NULL on failure.

  Example:
    (helper-ringbuf-reserve :r1 :r2 :r3)
    ;; r0 = pointer to reserved space or NULL"
  [ringbuf-reg size-reg flags-reg]
  [(mov-reg :r1 ringbuf-reg)
   (mov-reg :r2 size-reg)
   (mov-reg :r3 flags-reg)
   (call 131)])  ; bpf_ringbuf_reserve = 131

(defn helper-ringbuf-submit
  "Call bpf_ringbuf_submit helper.

  Submit reserved ring buffer data.

  Parameters:
  - data-reg: Register containing pointer from bpf_ringbuf_reserve
  - flags-reg: Register containing flags

  No return value (void).

  Example:
    (helper-ringbuf-submit :r1 :r2)"
  [data-reg flags-reg]
  [(mov-reg :r1 data-reg)
   (mov-reg :r2 flags-reg)
   (call 132)])  ; bpf_ringbuf_submit = 132

(defn helper-ringbuf-discard
  "Call bpf_ringbuf_discard helper.

  Discard reserved ring buffer space without submitting.

  Parameters:
  - data-reg: Register containing pointer from bpf_ringbuf_reserve
  - flags-reg: Register containing flags

  No return value (void).

  Example:
    (helper-ringbuf-discard :r1 :r2)"
  [data-reg flags-reg]
  [(mov-reg :r1 data-reg)
   (mov-reg :r2 flags-reg)
   (call 133)])  ; bpf_ringbuf_discard = 133

(defn ringbuf-reserve
  "Reserve space in ring buffer, returning pointer in dst-reg.

  Higher-level function that loads the map FD and calls bpf_ringbuf_reserve.
  The reserved pointer is returned in dst-reg (moved from r0).

  Parameters:
  - dst-reg: Destination register for reserved pointer
  - map-fd: Ring buffer map file descriptor (integer)
  - size: Size to reserve (integer, must be 8-byte aligned)

  Returns instruction sequence. After execution:
  - dst-reg = pointer to reserved space, or NULL on failure

  Example:
    (ringbuf-reserve :r6 ringbuf-map-fd 48)
    ;; r6 = reserved pointer (check for NULL before use!)

  Typical pattern:
    (concat
      (ringbuf-reserve :r6 map-fd 48)
      ;; Check for NULL
      [(jmp-imm :jeq :r6 0 error-offset)]
      ;; Write to r6 + offset
      [(stx :dw :r6 :r7 0)]  ; store data
      (ringbuf-submit :r6))"
  [dst-reg map-fd size]
  (vec (concat
        [(ld-map-fd :r1 map-fd)]  ; r1 = map fd
        [(mov :r2 size)]           ; r2 = size
        [(mov :r3 0)]              ; r3 = flags (0 for normal)
        [(call 131)]               ; bpf_ringbuf_reserve
        [(mov-reg dst-reg :r0)]))) ; dst = result

(defn ringbuf-submit
  "Submit reserved ring buffer data.

  Submits data that was previously reserved with ringbuf-reserve.
  After calling this, the reserved pointer is no longer valid.

  Parameters:
  - data-reg: Register containing pointer from ringbuf-reserve

  Returns instruction sequence.

  Example:
    (ringbuf-submit :r6)
    ;; Submits data at r6 to consumers"
  [data-reg]
  [(mov-reg :r1 data-reg)
   (mov :r2 0)   ; flags = 0
   (call 132)])  ; bpf_ringbuf_submit

(defn ringbuf-discard
  "Discard reserved ring buffer data without submitting.

  Discards data that was previously reserved with ringbuf-reserve.
  Use this instead of submit if you decide not to send the event.
  After calling this, the reserved pointer is no longer valid.

  Parameters:
  - data-reg: Register containing pointer from ringbuf-reserve

  Returns instruction sequence.

  Example:
    (ringbuf-discard :r6)
    ;; Discards reserved space at r6"
  [data-reg]
  [(mov-reg :r1 data-reg)
   (mov :r2 0)   ; flags = 0
   (call 133)])  ; bpf_ringbuf_discard

;; === Debug Helpers ===

(defn helper-trace-printk
  "Call bpf_trace_printk helper.

  Print debug message to trace pipe (/sys/kernel/debug/tracing/trace_pipe).
  WARNING: Use only for debugging! Has performance overhead.

  Parameters:
  - fmt-reg: Register containing format string pointer
  - fmt-size-reg: Register containing format string size
  - arg1-reg: Register containing first argument (optional)
  - arg2-reg: Register containing second argument (optional)
  - arg3-reg: Register containing third argument (optional)

  Returns number of bytes written, or negative on error.

  Example:
    (helper-trace-printk :r1 :r2 :r3 :r4 :r5)"
  ([fmt-reg fmt-size-reg]
   [(mov-reg :r1 fmt-reg)
    (mov-reg :r2 fmt-size-reg)
    (call 6)])  ; bpf_trace_printk = 6
  ([fmt-reg fmt-size-reg arg1-reg]
   [(mov-reg :r1 fmt-reg)
    (mov-reg :r2 fmt-size-reg)
    (mov-reg :r3 arg1-reg)
    (call 6)])
  ([fmt-reg fmt-size-reg arg1-reg arg2-reg]
   [(mov-reg :r1 fmt-reg)
    (mov-reg :r2 fmt-size-reg)
    (mov-reg :r3 arg1-reg)
    (mov-reg :r4 arg2-reg)
    (call 6)])
  ([fmt-reg fmt-size-reg arg1-reg arg2-reg arg3-reg]
   [(mov-reg :r1 fmt-reg)
    (mov-reg :r2 fmt-size-reg)
    (mov-reg :r3 arg1-reg)
    (mov-reg :r4 arg2-reg)
    (mov-reg :r5 arg3-reg)
    (call 6)]))

;; === Control Flow Helpers ===

(defn helper-tail-call
  "Call bpf_tail_call helper.

  Tail call to another BPF program. Never returns on success.

  Parameters:
  - ctx-reg: Register containing context pointer
  - prog-array-reg: Register containing program array map FD
  - index-reg: Register containing program index

  Never returns on success. Falls through on failure.

  Example:
    (helper-tail-call :r1 :r2 :r3)
    ;; Program continues here only if tail call failed"
  [ctx-reg prog-array-reg index-reg]
  [(mov-reg :r1 ctx-reg)
   (mov-reg :r2 prog-array-reg)
   (mov-reg :r3 index-reg)
   (call 12)])  ; bpf_tail_call = 12

(defn helper-loop
  "Call bpf_loop helper.

  Execute callback function in a bounded loop (up to nr-loops iterations).

  Parameters:
  - nr-loops-reg: Register containing number of iterations
  - callback-fn-reg: Register containing callback function pointer
  - callback-ctx-reg: Register containing callback context pointer
  - flags-reg: Register containing flags

  Returns number of iterations completed.

  Example:
    (helper-loop :r1 :r2 :r3 :r4)"
  [nr-loops-reg callback-fn-reg callback-ctx-reg flags-reg]
  [(mov-reg :r1 nr-loops-reg)
   (mov-reg :r2 callback-fn-reg)
   (mov-reg :r3 callback-ctx-reg)
   (mov-reg :r4 flags-reg)
   (call 168)])  ; bpf_loop = 168

;; === Cgroup Helpers ===

(defn helper-get-current-cgroup-id
  "Call bpf_get_current_cgroup_id helper.

  Get current cgroup ID.

  Returns cgroup ID in r0.

  Example:
    (helper-get-current-cgroup-id)
    ;; r0 = current cgroup ID"
  []
  [(call 80)])  ; bpf_get_current_cgroup_id = 80

(defn helper-get-current-ancestor-cgroup-id
  "Call bpf_get_current_ancestor_cgroup_id helper.

  Get ancestor cgroup ID at specified level.

  Parameters:
  - ancestor-level-reg: Register containing ancestor level

  Returns ancestor cgroup ID in r0.

  Example:
    (helper-get-current-ancestor-cgroup-id :r1)"
  [ancestor-level-reg]
  [(mov-reg :r1 ancestor-level-reg)
   (call 123)])  ; bpf_get_current_ancestor_cgroup_id = 123

;; === Synchronization Helpers ===

(defn helper-spin-lock
  "Call bpf_spin_lock helper.

  Acquire a spinlock.

  Parameters:
  - lock-reg: Register containing pointer to bpf_spin_lock

  No return value (void).

  Example:
    (helper-spin-lock :r1)"
  [lock-reg]
  [(mov-reg :r1 lock-reg)
   (call 93)])  ; bpf_spin_lock = 93

(defn helper-spin-unlock
  "Call bpf_spin_unlock helper.

  Release a spinlock.

  Parameters:
  - lock-reg: Register containing pointer to bpf_spin_lock

  No return value (void).

  Example:
    (helper-spin-unlock :r1)"
  [lock-reg]
  [(mov-reg :r1 lock-reg)
   (call 94)])  ; bpf_spin_unlock = 94

;; === Utility Helpers ===

(defn helper-snprintf
  "Call bpf_snprintf helper.

  Format string to buffer (printf-style).

  Parameters:
  - str-reg: Register containing destination buffer pointer
  - str-size-reg: Register containing buffer size
  - fmt-reg: Register containing format string pointer
  - data-reg: Register containing data pointer
  - data-len-reg: Register containing data length

  Returns number of bytes written (excluding null terminator).

  Example:
    (helper-snprintf :r1 :r2 :r3 :r4 :r5)"
  [str-reg str-size-reg fmt-reg data-reg data-len-reg]
  [(mov-reg :r1 str-reg)
   (mov-reg :r2 str-size-reg)
   (mov-reg :r3 fmt-reg)
   (mov-reg :r4 data-reg)
   (mov-reg :r5 data-len-reg)
   (call 152)])  ; bpf_snprintf = 152

(defn helper-strncmp
  "Call bpf_strncmp helper.

  Compare two strings.

  Parameters:
  - s1-reg: Register containing first string pointer
  - s1-len-reg: Register containing first string length
  - s2-reg: Register containing second string pointer

  Returns 0 if equal, < 0 if s1 < s2, > 0 if s1 > s2.

  Example:
    (helper-strncmp :r1 :r2 :r3)"
  [s1-reg s1-len-reg s2-reg]
  [(mov-reg :r1 s1-reg)
   (mov-reg :r2 s1-len-reg)
   (mov-reg :r3 s2-reg)
   (call 169)])  ; bpf_strncmp = 169

;; ============================================================================
;; High-Level Helper Patterns and Macros
;; ============================================================================
;;
;; These functions provide common patterns and idioms for using BPF helpers.

(defn with-map-lookup
  "Generate map lookup with NULL check pattern.

  Looks up a map element and jumps to the specified offset if NULL.

  Parameters:
  - map-reg: Register containing map FD
  - key-reg: Register containing key pointer
  - null-jump-offset: Jump offset if lookup returns NULL
  - result-reg: Register to store the result (default :r0)

  Returns instruction sequence. Result pointer is in result-reg.

  Example:
    (with-map-lookup :r1 :r2 5 :r6)
    ;; r6 = map_lookup(r1, r2)
    ;; if (r6 == NULL) jump forward 5 instructions"
  ([map-reg key-reg null-jump-offset]
   (with-map-lookup map-reg key-reg null-jump-offset :r0))
  ([map-reg key-reg null-jump-offset result-reg]
   (vec (concat
         (helper-map-lookup-elem map-reg key-reg)
         [(mov-reg result-reg :r0)  ; Save result
          (jmp-imm :jeq result-reg 0 null-jump-offset)]))))  ; Jump if NULL

(defn safe-probe-read
  "Generate safe probe read with error checking.

  Reads from unsafe pointer and checks for errors.

  Parameters:
  - dst-reg: Destination buffer register
  - size: Size to read (immediate value)
  - src-reg: Source pointer register
  - error-jump-offset: Jump offset on error

  Returns instruction sequence.

  Example:
    (safe-probe-read :r1 4 :r2 10)
    ;; Reads 4 bytes from r2 to r1
    ;; Jumps forward 10 instructions on error"
  [dst-reg size src-reg error-jump-offset]
  (vec (concat
        [(mov dst-reg 0)]  ; Clear destination
        [(mov :r7 size)]   ; Size in r7
        (helper-probe-read-kernel dst-reg :r7 src-reg)
        ;; r0 = 0 on success, < 0 on error
        [(jmp-imm :jslt :r0 0 error-jump-offset)])))  ; Jump if error

(defn get-process-info
  "Generate code to collect full process information.

  Collects PID, TGID, UID, GID, and command name.

  Parameters:
  - pid-tgid-reg: Register to store combined PID/TGID (default :r6)
  - uid-gid-reg: Register to store combined UID/GID (default :r7)
  - comm-buf-reg: Register containing comm buffer pointer (optional)
  - comm-size: Size of comm buffer (default 16)

  Returns instruction sequence.

  Example:
    (get-process-info :r6 :r7 :r8)
    ;; r6 = (tgid << 32) | pid
    ;; r7 = (gid << 32) | uid
    ;; buffer at r8 = comm"
  ([pid-tgid-reg uid-gid-reg]
   (vec (concat
         (helper-get-current-pid-tgid)
         [(mov-reg pid-tgid-reg :r0)]
         (helper-get-current-uid-gid)
         [(mov-reg uid-gid-reg :r0)])))
  ([pid-tgid-reg uid-gid-reg comm-buf-reg]
   (get-process-info pid-tgid-reg uid-gid-reg comm-buf-reg 16))
  ([pid-tgid-reg uid-gid-reg comm-buf-reg comm-size]
   (vec (concat
         (helper-get-current-pid-tgid)
         [(mov-reg pid-tgid-reg :r0)]
         (helper-get-current-uid-gid)
         [(mov-reg uid-gid-reg :r0)]
         [(mov :r7 comm-size)]
         (helper-get-current-comm comm-buf-reg :r7)))))

(defn time-delta
  "Generate code to measure time delta between two points.

  Uses ktime-get-ns to measure elapsed time.

  Parameters:
  - start-time-reg: Register to store start time
  - delta-reg: Register to store time delta (optional, default :r0)

  Returns two instruction sequences:
  1. Start: Get start time
  2. End: Calculate delta

  Example:
    (let [[start end] (time-delta :r6 :r7)]
      (concat
        start
        ;; ... code to measure ...
        end))
    ;; r6 = start time
    ;; r7 = end time - start time"
  ([start-time-reg]
   (time-delta start-time-reg :r0))
  ([start-time-reg delta-reg]
   [(vec (concat
          (helper-ktime-get-ns)
          [(mov-reg start-time-reg :r0)]))  ; Start
    (vec (concat
          (helper-ktime-get-ns)
          [(sub-reg :r0 start-time-reg)  ; delta = now - start
           (mov-reg delta-reg :r0)]))]))  ; End

(defn filter-by-pid
  "Generate code to filter by process ID.

  Only continues if PID matches, otherwise jumps to offset.

  Parameters:
  - target-pid: PID to match (immediate value)
  - skip-jump-offset: Jump offset if PID doesn't match

  Returns instruction sequence.

  Example:
    (filter-by-pid 1234 20)
    ;; Jumps forward 20 instructions if current PID != 1234"
  [target-pid skip-jump-offset]
  (vec (concat
        (helper-get-current-pid-tgid)
        ;; Extract PID from lower 32 bits
        [(and-op :r0 0xFFFFFFFF)]  ; Mask to get PID
        [(jmp-imm :jne :r0 target-pid skip-jump-offset)])))

(defn filter-by-uid
  "Generate code to filter by user ID.

  Only continues if UID matches, otherwise jumps to offset.

  Parameters:
  - target-uid: UID to match (immediate value)
  - skip-jump-offset: Jump offset if UID doesn't match

  Returns instruction sequence.

  Example:
    (filter-by-uid 1000 20)
    ;; Jumps forward 20 instructions if current UID != 1000"
  [target-uid skip-jump-offset]
  (vec (concat
        (helper-get-current-uid-gid)
        ;; Extract UID from lower 32 bits
        [(and-op :r0 0xFFFFFFFF)]  ; Mask to get UID
        [(jmp-imm :jne :r0 target-uid skip-jump-offset)])))

(defn sample-one-in-n
  "Generate code to sample 1 in N events.

  Uses random number generation for probabilistic sampling.

  Parameters:
  - n: Sample rate (keep 1 in N events)
  - skip-jump-offset: Jump offset if event should be dropped

  Returns instruction sequence.

  Example:
    (sample-one-in-n 100 20)
    ;; Drops ~99% of events, keeps ~1%"
  [n skip-jump-offset]
  (vec (concat
        (helper-get-prandom-u32)
        [(mod :r0 n)]  ; r0 = random % n
        [(jmp-imm :jne :r0 0 skip-jump-offset)])))  ; Skip if not 0

(defn trace-println
  "Generate code for simple trace printing (debug only).

  Simplified interface for bpf_trace_printk with a string message.

  Parameters:
  - msg-reg: Register containing format string pointer
  - msg-len: Length of format string
  - arg-regs: Optional argument registers (up to 3)

  Returns instruction sequence.

  WARNING: Use only for debugging!

  Example:
    (trace-println :r1 14)  ; Just format string
    (trace-println :r1 14 :r2 :r3)  ; With arguments"
  ([msg-reg msg-len]
   [(mov :r7 msg-len)
    (flatten (helper-trace-printk msg-reg :r7))])
  ([msg-reg msg-len arg1]
   [(mov :r7 msg-len)
    (flatten (helper-trace-printk msg-reg :r7 arg1))])
  ([msg-reg msg-len arg1 arg2]
   [(mov :r7 msg-len)
    (flatten (helper-trace-printk msg-reg :r7 arg1 arg2))])
  ([msg-reg msg-len arg1 arg2 arg3]
   [(mov :r7 msg-len)
    (flatten (helper-trace-printk msg-reg :r7 arg1 arg2 arg3))]))

(defn ringbuf-output-event
  "Generate code to output an event to ring buffer with error handling.

  Combines helper call with error checking.

  Parameters:
  - ringbuf-map-reg: Register with ring buffer map FD
  - event-ptr-reg: Register with event data pointer
  - event-size: Size of event data (immediate or register)
  - error-jump-offset: Jump offset on error (optional)

  Returns instruction sequence.

  Example:
    (ringbuf-output-event :r1 :r2 64 10)
    ;; Output 64 bytes from r2 to ringbuf r1
    ;; Jump forward 10 instructions on error"
  ([ringbuf-map-reg event-ptr-reg event-size]
   (vec (concat
         (if (keyword? event-size)
           (helper-ringbuf-output ringbuf-map-reg event-ptr-reg event-size :r0)
           [(mov :r8 event-size)
            (flatten (helper-ringbuf-output ringbuf-map-reg event-ptr-reg :r8 :r0))]))))
  ([ringbuf-map-reg event-ptr-reg event-size error-jump-offset]
   (vec (concat
         (ringbuf-output-event ringbuf-map-reg event-ptr-reg event-size)
         ;; r0 = 0 on success, < 0 on error
         [(jmp-imm :jslt :r0 0 error-jump-offset)]))))

(defn with-spinlock
  "Generate code to execute a critical section with spinlock protection.

  Acquires lock, executes code, and releases lock.

  Parameters:
  - lock-ptr-reg: Register containing pointer to bpf_spin_lock
  - body-insns: Instruction sequence to execute while holding lock

  Returns instruction sequence.

  Example:
    (with-spinlock :r1 [(mov :r0 42) (exit-insn)])
    ;; Acquires lock, sets r0=42, releases lock, exits"
  [lock-ptr-reg body-insns]
  (vec (concat
        (helper-spin-lock lock-ptr-reg)
        body-insns
        (helper-spin-unlock lock-ptr-reg))))

(defn bounded-loop
  "Generate code for a bounded loop using bpf_loop helper.

  Executes callback function up to N times.

  Parameters:
  - iterations: Number of iterations (immediate or register)
  - callback-fn-reg: Register containing callback function pointer
  - callback-ctx-reg: Register containing callback context (optional)

  Returns instruction sequence.

  Example:
    (bounded-loop 10 :r1 :r2)
    ;; Calls function at r1 up to 10 times with ctx r2"
  ([iterations callback-fn-reg]
   (bounded-loop iterations callback-fn-reg :r0))
  ([iterations callback-fn-reg callback-ctx-reg]
   (vec (if (keyword? iterations)
          (helper-loop iterations callback-fn-reg callback-ctx-reg :r0)
          (concat
           [(mov :r8 iterations)]
           (helper-loop :r8 callback-fn-reg callback-ctx-reg :r0))))))

(defn stack-allocate
  "Generate code to allocate space on the BPF stack.

  Adjusts r10 (frame pointer) to create stack space.

  Parameters:
  - size: Number of bytes to allocate
  - ptr-reg: Register to receive pointer to allocated space

  Returns instruction sequence.

  Example:
    (stack-allocate 64 :r1)
    ;; r1 = pointer to 64 bytes on stack"
  [size ptr-reg]
  [(mov-reg ptr-reg :r10)  ; ptr = frame pointer
   (add ptr-reg (- size))  ; ptr -= size (move down stack)
   ])

(defn extract-pid
  "Extract PID from combined PID/TGID value.

  Parameters:
  - pid-tgid-reg: Register containing combined value
  - pid-reg: Register to receive PID

  Returns instruction sequence.

  Example:
    (extract-pid :r0 :r1)
    ;; r1 = r0 & 0xFFFFFFFF"
  [pid-tgid-reg pid-reg]
  [(mov-reg pid-reg pid-tgid-reg)
   (and-op pid-reg 0xFFFFFFFF)])

(defn extract-tgid
  "Extract TGID from combined PID/TGID value.

  Parameters:
  - pid-tgid-reg: Register containing combined value
  - tgid-reg: Register to receive TGID

  Returns instruction sequence.

  Example:
    (extract-tgid :r0 :r1)
    ;; r1 = r0 >> 32"
  [pid-tgid-reg tgid-reg]
  [(mov-reg tgid-reg pid-tgid-reg)
   (rsh tgid-reg 32)])

(defn extract-uid
  "Extract UID from combined UID/GID value.

  Parameters:
  - uid-gid-reg: Register containing combined value
  - uid-reg: Register to receive UID

  Returns instruction sequence.

  Example:
    (extract-uid :r0 :r1)
    ;; r1 = r0 & 0xFFFFFFFF"
  [uid-gid-reg uid-reg]
  [(mov-reg uid-reg uid-gid-reg)
   (and-op uid-reg 0xFFFFFFFF)])

(defn extract-gid
  "Extract GID from combined UID/GID value.

  Parameters:
  - uid-gid-reg: Register containing combined value
  - gid-reg: Register to receive GID

  Returns instruction sequence.

  Example:
    (extract-gid :r0 :r1)
    ;; r1 = r0 >> 32"
  [uid-gid-reg gid-reg]
  [(mov-reg gid-reg uid-gid-reg)
   (rsh gid-reg 32)])

;; ============================================================================
;; Atomic Operations
;; ============================================================================
;;
;; BPF supports atomic operations on memory for thread-safe updates.
;; These are essential for per-CPU counters and lock-free data structures.
;;
;; Atomic operations use STX instruction class with ATOMIC mode (0xc0).
;; The operation type is encoded in the immediate field.

(def ^:private atomic-op
  "Atomic operation codes (encoded in immediate field)"
  {:add   0x00   ; atomic add
   :or    0x40   ; atomic or
   :and   0x50   ; atomic and
   :xor   0xa0   ; atomic xor
   :xchg  0xe1   ; atomic exchange
   :cmpxchg 0xf1 ; atomic compare-and-exchange
   })

(def ^:private atomic-fetch-flag
  "Flag to indicate fetch variant (returns old value)"
  0x01)

(defn- build-atomic-instruction
  "Build an atomic BPF instruction.

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Destination register (memory address base)
  - src: Source register (value to use in operation)
  - offset: Memory offset from dst
  - op: Atomic operation keyword
  - fetch?: Whether to fetch old value into src

  Returns byte array (8 bytes)"
  [size dst src offset op fetch?]
  (let [size-bits (get load-store-size size)
        opcode (bit-or size-bits
                       (get load-store-mode :atomic)
                       (get instruction-class :stx))
        dst-reg (resolve-register dst)
        src-reg (resolve-register src)
        imm-op (get atomic-op op)
        imm (if fetch?
              (bit-or imm-op atomic-fetch-flag)
              imm-op)]
    (build-instruction opcode dst-reg src-reg offset imm)))

;; === Basic Atomic Operations ===

(defn atomic-add
  "Atomic add to memory location.

  Performs: *dst[offset] += src

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to add
  - offset: Memory offset (default 0)

  Example:
    (atomic-add :dw :r1 :r2 0)  ; *(u64*)(r1+0) += r2"
  ([size dst src]
   (atomic-add size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :add false)))

(defn atomic-fetch-add
  "Atomic fetch-and-add: returns old value, then adds.

  Performs: src = *dst[offset]; *dst[offset] += src
  (Note: src receives the OLD value, not the new value)

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to add (receives old value)
  - offset: Memory offset (default 0)

  Example:
    (atomic-fetch-add :dw :r1 :r2 0)  ; r2 = *(r1+0); *(r1+0) += old_r2"
  ([size dst src]
   (atomic-fetch-add size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :add true)))

(defn atomic-or
  "Atomic OR to memory location.

  Performs: *dst[offset] |= src

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to OR
  - offset: Memory offset (default 0)

  Example:
    (atomic-or :dw :r1 :r2 0)  ; *(u64*)(r1+0) |= r2"
  ([size dst src]
   (atomic-or size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :or false)))

(defn atomic-fetch-or
  "Atomic fetch-and-OR: returns old value, then ORs.

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to OR (receives old value)
  - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-fetch-or size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :or true)))

(defn atomic-and
  "Atomic AND to memory location.

  Performs: *dst[offset] &= src

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to AND
  - offset: Memory offset (default 0)

  Example:
    (atomic-and :dw :r1 :r2 0)  ; *(u64*)(r1+0) &= r2"
  ([size dst src]
   (atomic-and size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :and false)))

(defn atomic-fetch-and
  "Atomic fetch-and-AND: returns old value, then ANDs.

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to AND (receives old value)
  - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-fetch-and size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :and true)))

(defn atomic-xor
  "Atomic XOR to memory location.

  Performs: *dst[offset] ^= src

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to XOR
  - offset: Memory offset (default 0)

  Example:
    (atomic-xor :dw :r1 :r2 0)  ; *(u64*)(r1+0) ^= r2"
  ([size dst src]
   (atomic-xor size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :xor false)))

(defn atomic-fetch-xor
  "Atomic fetch-and-XOR: returns old value, then XORs.

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing value to XOR (receives old value)
  - offset: Memory offset (default 0)"
  ([size dst src]
   (atomic-fetch-xor size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :xor true)))

(defn atomic-xchg
  "Atomic exchange: swap register value with memory value.

  Performs: src = xchg(*dst[offset], src)
  The old memory value is placed in src, and src's old value
  is written to memory.

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register to exchange with memory
  - offset: Memory offset (default 0)

  Example:
    (atomic-xchg :dw :r1 :r2 0)  ; r2 <=> *(r1+0)"
  ([size dst src]
   (atomic-xchg size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :xchg false)))

(defn atomic-cmpxchg
  "Atomic compare-and-exchange (CAS).

  Performs:
  - If *dst[offset] == r0, then *dst[offset] = src
  - r0 receives the original value of *dst[offset]

  Note: r0 is implicitly used as the comparison value.

  Parameters:
  - size: :w (32-bit) or :dw (64-bit)
  - dst: Register containing memory address
  - src: Register containing new value to write if comparison succeeds
  - offset: Memory offset (default 0)

  Example:
    ;; Compare-and-swap pattern:
    (mov :r0 expected-value)
    (mov :r2 new-value)
    (atomic-cmpxchg :dw :r1 :r2 0)
    ;; r0 now contains original value
    ;; Memory updated only if original == expected-value"
  ([size dst src]
   (atomic-cmpxchg size dst src 0))
  ([size dst src offset]
   (build-atomic-instruction size dst src offset :cmpxchg false)))

;; === High-Level Atomic Patterns ===

(defn atomic-increment
  "Generate code to atomically increment a counter.

  Uses atomic-fetch-add with value 1.

  Parameters:
  - addr-reg: Register containing counter address
  - offset: Memory offset (default 0)

  Returns instruction sequence.

  Example:
    (atomic-increment :r1 0)  ; (*r1)++ atomically"
  ([addr-reg]
   (atomic-increment addr-reg 0))
  ([addr-reg offset]
   [(mov :r3 1)  ; Use r3 as temp for increment value
    (atomic-add :dw addr-reg :r3 offset)]))

(defn atomic-decrement
  "Generate code to atomically decrement a counter.

  Uses atomic-add with value -1.

  Parameters:
  - addr-reg: Register containing counter address
  - offset: Memory offset (default 0)

  Returns instruction sequence.

  Example:
    (atomic-decrement :r1 0)  ; (*r1)-- atomically"
  ([addr-reg]
   (atomic-decrement addr-reg 0))
  ([addr-reg offset]
   [(mov :r3 -1)  ; Use r3 as temp
    (atomic-add :dw addr-reg :r3 offset)]))

(defn atomic-set-bit
  "Generate code to atomically set a bit.

  Uses atomic-or to set the specified bit.

  Parameters:
  - addr-reg: Register containing memory address
  - bit: Bit number to set (0-63)
  - offset: Memory offset (default 0)

  Returns instruction sequence.

  Example:
    (atomic-set-bit :r1 5 0)  ; Set bit 5 in *r1"
  ([addr-reg bit]
   (atomic-set-bit addr-reg bit 0))
  ([addr-reg bit offset]
   [(mov :r3 (bit-shift-left 1 bit))
    (atomic-or :dw addr-reg :r3 offset)]))

(defn atomic-clear-bit
  "Generate code to atomically clear a bit.

  Uses atomic-and with inverted bit mask.

  Parameters:
  - addr-reg: Register containing memory address
  - bit: Bit number to clear (0-63)
  - offset: Memory offset (default 0)

  Returns instruction sequence.

  Example:
    (atomic-clear-bit :r1 5 0)  ; Clear bit 5 in *r1"
  ([addr-reg bit]
   (atomic-clear-bit addr-reg bit 0))
  ([addr-reg bit offset]
   [(mov :r3 (bit-not (bit-shift-left 1 bit)))
    (atomic-and :dw addr-reg :r3 offset)]))

(defn atomic-toggle-bit
  "Generate code to atomically toggle (flip) a bit.

  Uses atomic-xor with the bit mask.

  Parameters:
  - addr-reg: Register containing memory address
  - bit: Bit number to toggle (0-63)
  - offset: Memory offset (default 0)

  Returns instruction sequence.

  Example:
    (atomic-toggle-bit :r1 5 0)  ; Toggle bit 5 in *r1"
  ([addr-reg bit]
   (atomic-toggle-bit addr-reg bit 0))
  ([addr-reg bit offset]
   [(mov :r3 (bit-shift-left 1 bit))
    (atomic-xor :dw addr-reg :r3 offset)]))

(defn cas-loop
  "Generate a compare-and-swap loop pattern.

  Attempts to atomically update a value from old to new.
  Retries if another CPU modified the value.

  Parameters:
  - addr-reg: Register containing memory address
  - expected-reg: Register containing expected old value
  - new-reg: Register containing new value to write
  - retry-offset: Jump offset to retry location (negative)
  - offset: Memory offset (default 0)

  Returns instruction sequence.

  Note: This is a template - actual implementation may need
  adjustment based on specific use case.

  Example:
    ;; Load current value into r6
    (ldx :dw :r6 :r1 0)
    ;; Prepare expected and new values
    (mov-reg :r0 :r6)      ; r0 = expected
    (add-reg :r2 :r6)      ; r2 = r6 + delta = new value
    ;; CAS
    (atomic-cmpxchg :dw :r1 :r2 0)
    ;; r0 now has original, compare with expected
    (jmp-reg :jne :r0 :r6 retry-offset)  ; retry if changed"
  ([addr-reg expected-reg new-reg retry-offset]
   (cas-loop addr-reg expected-reg new-reg retry-offset 0))
  ([addr-reg expected-reg new-reg retry-offset offset]
   [;; Move expected value to r0 (required for cmpxchg)
    (mov-reg :r0 expected-reg)
    ;; Perform CAS
    (atomic-cmpxchg :dw addr-reg new-reg offset)
    ;; Compare r0 (old value) with expected
    (jmp-reg :jne :r0 expected-reg retry-offset)]))

(comment
  "Atomic Operations Usage Examples"

  ;; Example 1: Simple counter increment
  (assemble
    [(mov-reg :r1 :r10)     ; r1 = frame pointer (stack)
     (add :r1 -8)           ; Point to counter on stack
     (atomic-increment :r1)
     (exit-insn)])

  ;; Example 2: Set a flag atomically
  (assemble
    [(ldx :dw :r1 :r6 0)    ; Load address from context
     (atomic-set-bit :r1 0)  ; Set bit 0 (flag enabled)
     (exit-insn)])

  ;; Example 3: Compare-and-swap to update if unchanged
  (assemble
    [(ldx :dw :r1 :r6 0)       ; r1 = address
     (ldx :dw :r6 :r1 0)       ; r6 = current value
     (mov-reg :r0 :r6)         ; r0 = expected (current)
     (mov :r2 42)              ; r2 = new value
     (atomic-cmpxchg :dw :r1 :r2 0)  ; Try to swap
     ;; r0 now contains what was actually there
     ;; If r0 == r6, swap succeeded; otherwise retry needed
     (exit-insn)])

  ;; Example 4: Atomic fetch-and-add for statistics
  (assemble
    [(ldx :dw :r1 :r6 0)       ; r1 = stats address
     (mov :r2 1)               ; Increment by 1
     (atomic-fetch-add :dw :r1 :r2 0)
     ;; r2 now contains the old count
     (mov-reg :r0 :r2)         ; Return old count
     (exit-insn)]))

(comment
  "Helper Pattern Usage Examples"

  ;; Example 1: Map lookup with NULL check
  (assemble
   (vec (concat
         ;; Setup map FD and key pointer in r1, r2
         (mov :r1 3)  ; map FD
         (mov-reg :r2 :r10)  ; key pointer
         ;; Lookup with NULL check
         (with-map-lookup :r1 :r2 5 :r6)
         ;; r6 now contains value pointer or NULL
         ;; If NULL, jumped forward 5 instructions
         ;; Use the value
         (ldx :w :r0 :r6 0)
         [(exit-insn)]
         ;; NULL handler (5 instructions forward)
         [(mov :r0 -1)
          (exit-insn)])))

  ;; Example 2: Process filtering and info collection
  (assemble
   (vec (concat
         ;; Filter by UID 1000
         (filter-by-uid 1000 10)
         ;; Collect process info
         (get-process-info :r6 :r7)
         ;; r6 = pid/tgid, r7 = uid/gid
         [(exit-insn)])))

  ;; Example 3: Time measurement
  (let [[start end] (time-delta :r6 :r7)]
    (assemble
     (vec (concat
           start  ; Start timer
           ;; Do some work...
           (helper-get-current-pid-tgid)
           end    ; Calculate delta
           ;; r7 now contains elapsed nanoseconds
           [(exit-insn)]))))

  ;; Example 4: Probabilistic sampling
  (assemble
   (vec (concat
         ;; Sample 1 in 100 events
         (sample-one-in-n 100 10)
         ;; Only ~1% of events reach here
         (helper-get-current-pid-tgid)
         [(exit-insn)]
         ;; Dropped events skip to here
         )))

  ;; Example 5: Safe probe read with error handling
  (assemble
   (vec (concat
         ;; r1 = destination buffer
         ;; r2 = source pointer
         (safe-probe-read :r1 8 :r2 5)
         ;; Read succeeded, use data
         [(mov :r0 0)
          (exit-insn)]
         ;; Error handler (5 instructions forward)
         [(mov :r0 -1)
          (exit-insn)])))

  ;; Example 6: Ring buffer event output
  (assemble
   (vec (concat
         ;; r1 = ringbuf map FD
         ;; r2 = event data pointer
         (ringbuf-output-event :r1 :r2 64 5)
         ;; Success
         [(mov :r0 0)
          (exit-insn)]
         ;; Error handler
         [(mov :r0 -1)
          (exit-insn)]))))
