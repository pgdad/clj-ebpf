(ns clj-ebpf.maps.helpers
  "BPF program instruction helpers for map operations.

   These functions generate instruction sequences for common map operations
   within BPF programs. They handle the setup of map FD loading, pointer
   construction, and helper calls.

   Unlike the functions in clj-ebpf.maps (which operate on maps from userspace),
   these helpers generate BPF bytecode for in-program map access.

   Usage example:
     (concat
       ;; ... set up key on stack at offset -16 ...
       (build-map-lookup my-map-fd -16)
       ;; r0 now contains pointer to value or NULL
       [(asm/jmp-imm :jeq :r0 0 :not-found)]
       ;; ... process value ...
       )"
  (:require [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; BPF Helper Function IDs
;; ============================================================================

(def ^:const BPF-FUNC-map-lookup-elem 1)
(def ^:const BPF-FUNC-map-update-elem 2)
(def ^:const BPF-FUNC-map-delete-elem 3)

;; Map update flags
(def ^:const BPF-ANY 0)       ; Create new element or update existing
(def ^:const BPF-NOEXIST 1)   ; Create new element only if it doesn't exist
(def ^:const BPF-EXIST 2)     ; Update existing element only

;; ============================================================================
;; Core Map Operation Helpers
;; ============================================================================

(defn build-map-lookup
  "Generate instructions for bpf_map_lookup_elem with map FD and stack key.

   This is a complete lookup sequence that:
   1. Loads the map FD into r1 using ld-map-fd (2 instructions)
   2. Sets r2 to point to the key on stack
   3. Calls bpf_map_lookup_elem

   Parameters:
     map-fd: The map file descriptor (integer)
     key-stack-off: Stack offset where key is stored (negative, e.g., -16)

   Result: r0 = pointer to value, or NULL if not found

   Clobbers: r0, r1, r2 (and r3-r5 by the helper call)

   Example:
     ;; Key is at stack[-16], 4 bytes
     (build-map-lookup conntrack-map-fd -16)
     ;; Check result
     [(asm/jmp-imm :jeq :r0 0 :key-not-found)]
     ;; r0 points to value"
  [map-fd key-stack-off]
  [(dsl/ld-map-fd :r1 map-fd)      ; r1 = map fd (2 instruction slots)
   (dsl/mov-reg :r2 :r10)          ; r2 = frame pointer
   (dsl/add :r2 key-stack-off)     ; r2 = &key
   (dsl/call BPF-FUNC-map-lookup-elem)])

(defn build-map-update
  "Generate instructions for bpf_map_update_elem with map FD and stack key/value.

   This is a complete update sequence that:
   1. Loads the map FD into r1 using ld-map-fd
   2. Sets r2 to point to the key on stack
   3. Sets r3 to point to the value on stack
   4. Sets r4 to the flags
   5. Calls bpf_map_update_elem

   Parameters:
     map-fd: The map file descriptor (integer)
     key-stack-off: Stack offset where key is stored (negative)
     value-stack-off: Stack offset where value is stored (negative)
     flags: Update flags:
            - BPF-ANY (0): Create or update
            - BPF-NOEXIST (1): Create only if doesn't exist
            - BPF-EXIST (2): Update only if exists

   Result: r0 = 0 on success, negative on error

   Clobbers: r0, r1, r2, r3, r4 (and r5 by the helper call)

   Example:
     ;; Key at stack[-16], value at stack[-32]
     (build-map-update my-map-fd -16 -32 BPF-ANY)"
  [map-fd key-stack-off value-stack-off flags]
  [(dsl/ld-map-fd :r1 map-fd)
   (dsl/mov-reg :r2 :r10)
   (dsl/add :r2 key-stack-off)
   (dsl/mov-reg :r3 :r10)
   (dsl/add :r3 value-stack-off)
   (dsl/mov :r4 flags)
   (dsl/call BPF-FUNC-map-update-elem)])

(defn build-map-delete
  "Generate instructions for bpf_map_delete_elem with map FD and stack key.

   This is a complete delete sequence that:
   1. Loads the map FD into r1 using ld-map-fd
   2. Sets r2 to point to the key on stack
   3. Calls bpf_map_delete_elem

   Parameters:
     map-fd: The map file descriptor (integer)
     key-stack-off: Stack offset where key is stored (negative)

   Result: r0 = 0 on success, negative on error (e.g., -ENOENT if not found)

   Clobbers: r0, r1, r2 (and r3-r5 by the helper call)

   Example:
     ;; Delete entry with key at stack[-16]
     (build-map-delete my-map-fd -16)"
  [map-fd key-stack-off]
  [(dsl/ld-map-fd :r1 map-fd)
   (dsl/mov-reg :r2 :r10)
   (dsl/add :r2 key-stack-off)
   (dsl/call BPF-FUNC-map-delete-elem)])

;; ============================================================================
;; Convenience Helpers
;; ============================================================================

(defn build-map-lookup-or-init
  "Generate instructions that look up a key, and if not found, initialize it.

   This pattern is common for counters, rate limiters, and connection tracking.

   Parameters:
     map-fd: The map file descriptor
     key-stack-off: Stack offset where key is stored
     init-value-stack-off: Stack offset where initial value is stored
                           (used if key doesn't exist)

   Result: r0 = pointer to value (either existing or newly created)
           Returns NULL only if the map is full and insert fails

   Note: After lookup, you should check for NULL. If NULL, the initialization
   failed (map full or other error).

   Clobbers: r0-r4

   Example:
     ;; Initialize counter to 0 if not exists
     (concat
       ;; Set up initial value (0) on stack at -32
       [(dsl/mov :r0 0)
        (dsl/stx :dw :r10 :r0 -32)]
       ;; Lookup or init
       (build-map-lookup-or-init counter-map-fd -16 -32)
       ;; r0 = pointer to counter)"
  [map-fd key-stack-off init-value-stack-off]
  ;; First try lookup
  (concat
    (build-map-lookup map-fd key-stack-off)
    ;; If found (r0 != NULL), skip initialization
    ;; Jump forward past the update+lookup (8 instructions)
    [(dsl/jmp-imm :jne :r0 0 8)]
    ;; Not found - insert initial value
    (build-map-update map-fd key-stack-off init-value-stack-off BPF-NOEXIST)
    ;; Lookup again to get pointer
    (build-map-lookup map-fd key-stack-off)))

(defn build-map-increment
  "Generate instructions to atomically increment a value in a per-CPU array map.

   This is a common pattern for counters. Works best with per-CPU maps
   to avoid contention.

   Parameters:
     map-fd: The map file descriptor (should be a per-CPU array or hash)
     key-stack-off: Stack offset where key is stored
     value-stack-off: Stack offset for temporary value storage (needs 8 bytes)
     increment: Amount to add (default 1)

   Clobbers: r0-r4, r9

   Note: This is NOT atomic across CPUs. For per-CPU maps, each CPU
   increments its own counter. Aggregate across CPUs in userspace.

   Example:
     ;; Increment packet counter
     (build-map-increment packet-counter-fd -8 -16 1)"
  ([map-fd key-stack-off value-stack-off]
   (build-map-increment map-fd key-stack-off value-stack-off 1))
  ([map-fd key-stack-off value-stack-off increment]
   (concat
     ;; Lookup current value
     (build-map-lookup map-fd key-stack-off)
     ;; If NULL, initialize to 0
     [(dsl/jmp-imm :jne :r0 0 3)
      ;; Initialize to 0
      (dsl/mov :r0 0)
      (dsl/stx :dw :r10 :r0 value-stack-off)
      (dsl/jmp 3)]  ; Skip to update
     ;; Load current value
     [(dsl/mov-reg :r9 :r0)           ; Save pointer
      (dsl/ldx :dw :r0 :r9 0)         ; Load value
      (dsl/stx :dw :r10 :r0 value-stack-off)]
     ;; Add increment
     [(dsl/ldx :dw :r0 :r10 value-stack-off)
      (dsl/add :r0 increment)
      (dsl/stx :dw :r10 :r0 value-stack-off)]
     ;; Update map
     (build-map-update map-fd key-stack-off value-stack-off BPF-ANY))))

;; ============================================================================
;; Register-based Variants
;; ============================================================================
;;
;; These variants work with keys/values that are already in registers
;; rather than on the stack. Useful when you have a pointer to data.

(defn build-map-lookup-ptr
  "Generate instructions for map lookup with key pointer in a register.

   Unlike build-map-lookup which computes key pointer from stack offset,
   this takes a register that already contains the key pointer.

   Parameters:
     map-fd: The map file descriptor
     key-ptr-reg: Register containing pointer to key

   Result: r0 = pointer to value, or NULL

   Clobbers: r0, r1, r2

   Example:
     ;; r6 contains pointer to key
     (build-map-lookup-ptr my-map-fd :r6)"
  [map-fd key-ptr-reg]
  [(dsl/ld-map-fd :r1 map-fd)
   (dsl/mov-reg :r2 key-ptr-reg)
   (dsl/call BPF-FUNC-map-lookup-elem)])

(defn build-map-update-ptr
  "Generate instructions for map update with key/value pointers in registers.

   Parameters:
     map-fd: The map file descriptor
     key-ptr-reg: Register containing pointer to key
     value-ptr-reg: Register containing pointer to value
     flags: Update flags (BPF-ANY, BPF-NOEXIST, BPF-EXIST)

   Result: r0 = 0 on success, negative on error

   Clobbers: r0-r4

   Example:
     ;; r6 = key pointer, r7 = value pointer
     (build-map-update-ptr my-map-fd :r6 :r7 BPF-ANY)"
  [map-fd key-ptr-reg value-ptr-reg flags]
  [(dsl/ld-map-fd :r1 map-fd)
   (dsl/mov-reg :r2 key-ptr-reg)
   (dsl/mov-reg :r3 value-ptr-reg)
   (dsl/mov :r4 flags)
   (dsl/call BPF-FUNC-map-update-elem)])

(defn build-map-delete-ptr
  "Generate instructions for map delete with key pointer in a register.

   Parameters:
     map-fd: The map file descriptor
     key-ptr-reg: Register containing pointer to key

   Result: r0 = 0 on success, negative on error

   Clobbers: r0, r1, r2

   Example:
     ;; r6 contains pointer to key
     (build-map-delete-ptr my-map-fd :r6)"
  [map-fd key-ptr-reg]
  [(dsl/ld-map-fd :r1 map-fd)
   (dsl/mov-reg :r2 key-ptr-reg)
   (dsl/call BPF-FUNC-map-delete-elem)])

;; ============================================================================
;; Socket Key Building Helpers
;; ============================================================================
;;
;; These helpers generate instruction sequences to extract 4-tuple or 5-tuple
;; socket keys from BPF context structures (bpf_sock_ops, sk_msg_md, etc.)
;; and store them on the stack for use with sockmap/sockhash lookups.

;; Context structure offsets for socket-related fields
;; These match the offsets defined in clj-ebpf.ctx

(def ^:private sock-ops-key-offsets
  "bpf_sock_ops field offsets for 4-tuple key extraction."
  {:remote-ip4   24   ; Network byte order
   :local-ip4    28   ; Network byte order
   :remote-port  64   ; Network byte order
   :local-port   68}) ; Host byte order (!)

(def ^:private sk-msg-key-offsets
  "sk_msg_md field offsets for 4-tuple key extraction."
  {:remote-ip4   20   ; Network byte order
   :local-ip4    24   ; Network byte order
   :remote-port  60   ; Network byte order
   :local-port   64}) ; Host byte order (!)

(def ^:private sk-buff-key-offsets
  "__sk_buff field offsets for 4-tuple key extraction."
  {:remote-ip4  124   ; Network byte order
   :local-ip4   128   ; Network byte order
   :remote-port 132   ; Network byte order
   :local-port  136}) ; Host byte order (!)

(def context-key-offsets
  "Map of context types to their 4-tuple field offsets.

   Supported context types:
   - :sock-ops   - For BPF_PROG_TYPE_SOCK_OPS programs (bpf_sock_ops)
   - :sk-msg     - For BPF_PROG_TYPE_SK_MSG programs (sk_msg_md)
   - :sk-skb     - For BPF_PROG_TYPE_SK_SKB programs (__sk_buff)
   - :tc         - For TC programs (__sk_buff, same as sk-skb)"
  {:sock-ops sock-ops-key-offsets
   :sk-msg   sk-msg-key-offsets
   :sk-skb   sk-buff-key-offsets
   :tc       sk-buff-key-offsets})

(defn build-sock-key
  "Generate instructions to build a 4-tuple socket key from context.

   Extracts remote_ip, local_ip, remote_port, local_port from the BPF context
   and stores them contiguously on the stack for use with sockmap/sockhash.

   The resulting 16-byte key structure on stack:
     offset+0:  remote_ip4  (4 bytes)
     offset+4:  local_ip4   (4 bytes)
     offset+8:  remote_port (4 bytes, stored as u32)
     offset+12: local_port  (4 bytes, stored as u32)

   Parameters:
     ctx-reg: Register containing pointer to BPF context
     key-stack-off: Stack offset where key will be stored (negative, e.g., -16)
     ctx-type: Context type keyword:
               - :sock-ops for bpf_sock_ops (SOCK_OPS programs)
               - :sk-msg for sk_msg_md (SK_MSG programs)
               - :sk-skb or :tc for __sk_buff (SK_SKB/TC programs)

   Clobbers: r0

   Note: remote_port is network byte order, local_port is host byte order.
   The key is stored as-is without byte order conversion. If your sockmap
   key format expects a specific byte order, perform conversion after building.

   Example:
     ;; In a SOCK_OPS program, build key at fp-16
     (concat
       (build-sock-key :r6 -16 :sock-ops)
       ;; Key is now at stack[-16], can use for sockmap lookup
       (build-map-lookup sockmap-fd -16))"
  [ctx-reg key-stack-off ctx-type]
  (let [offsets (or (get context-key-offsets ctx-type)
                    (throw (ex-info "Unknown context type for sock key"
                                    {:ctx-type ctx-type
                                     :supported (keys context-key-offsets)})))]
    [(dsl/ldx :w :r0 ctx-reg (:remote-ip4 offsets))
     (dsl/stx :w :r10 :r0 key-stack-off)
     (dsl/ldx :w :r0 ctx-reg (:local-ip4 offsets))
     (dsl/stx :w :r10 :r0 (+ key-stack-off 4))
     (dsl/ldx :w :r0 ctx-reg (:remote-port offsets))
     (dsl/stx :w :r10 :r0 (+ key-stack-off 8))
     (dsl/ldx :w :r0 ctx-reg (:local-port offsets))
     (dsl/stx :w :r10 :r0 (+ key-stack-off 12))]))

(defn build-sock-key-ipv6
  "Generate instructions to build a 6-tuple IPv6 socket key from context.

   Extracts remote_ip6 (16 bytes), local_ip6 (16 bytes), remote_port, local_port
   from the BPF context for IPv6 connections.

   The resulting 40-byte key structure on stack:
     offset+0:  remote_ip6  (16 bytes)
     offset+16: local_ip6   (16 bytes)
     offset+32: remote_port (4 bytes)
     offset+36: local_port  (4 bytes)

   Parameters:
     ctx-reg: Register containing pointer to BPF context
     key-stack-off: Stack offset where key will be stored (negative, e.g., -48)
     ctx-type: Context type (:sock-ops only currently)

   Clobbers: r0

   Note: Only :sock-ops context is supported for IPv6 key building.

   Example:
     (concat
       (build-sock-key-ipv6 :r6 -48 :sock-ops)
       (build-map-lookup sockmap6-fd -48))"
  [ctx-reg key-stack-off ctx-type]
  (when (not= ctx-type :sock-ops)
    (throw (ex-info "IPv6 sock key only supported for :sock-ops context"
                    {:ctx-type ctx-type})))
  ;; bpf_sock_ops IPv6 offsets
  (let [remote-ip6-off 32   ; 16 bytes
        local-ip6-off  48   ; 16 bytes
        remote-port-off 64
        local-port-off 68]
    ;; Copy 16 bytes of remote_ip6 (4 loads of 4 bytes each)
    (concat
      [(dsl/ldx :w :r0 ctx-reg remote-ip6-off)
       (dsl/stx :w :r10 :r0 key-stack-off)
       (dsl/ldx :w :r0 ctx-reg (+ remote-ip6-off 4))
       (dsl/stx :w :r10 :r0 (+ key-stack-off 4))
       (dsl/ldx :w :r0 ctx-reg (+ remote-ip6-off 8))
       (dsl/stx :w :r10 :r0 (+ key-stack-off 8))
       (dsl/ldx :w :r0 ctx-reg (+ remote-ip6-off 12))
       (dsl/stx :w :r10 :r0 (+ key-stack-off 12))]
      ;; Copy 16 bytes of local_ip6
      [(dsl/ldx :w :r0 ctx-reg local-ip6-off)
       (dsl/stx :w :r10 :r0 (+ key-stack-off 16))
       (dsl/ldx :w :r0 ctx-reg (+ local-ip6-off 4))
       (dsl/stx :w :r10 :r0 (+ key-stack-off 20))
       (dsl/ldx :w :r0 ctx-reg (+ local-ip6-off 8))
       (dsl/stx :w :r10 :r0 (+ key-stack-off 24))
       (dsl/ldx :w :r0 ctx-reg (+ local-ip6-off 12))
       (dsl/stx :w :r10 :r0 (+ key-stack-off 28))]
      ;; Copy ports
      [(dsl/ldx :w :r0 ctx-reg remote-port-off)
       (dsl/stx :w :r10 :r0 (+ key-stack-off 32))
       (dsl/ldx :w :r0 ctx-reg local-port-off)
       (dsl/stx :w :r10 :r0 (+ key-stack-off 36))])))
