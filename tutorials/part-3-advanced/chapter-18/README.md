# Chapter 18: Multi-Program Coordination

**Duration**: 3-4 hours | **Difficulty**: Advanced

This chapter covers techniques for coordinating multiple BPF programs, including tail calls, program chaining, shared state management, and building composable BPF systems.

## Learning Objectives

By the end of this chapter, you will:
- Understand tail call mechanics and use cases
- Implement program chaining with shared state
- Build composable BPF program architectures
- Coordinate multiple programs through maps
- Handle versioning and updates in multi-program systems

## Prerequisites

- Completed Chapters 10-17
- Understanding of BPF program types
- Familiarity with concurrent programming

---

## 18.1 Why Multiple Programs?

### Single Program Limitations

A single BPF program has limitations:
- **Complexity limit**: 1M verified instructions
- **Stack limit**: 512 bytes
- **Single responsibility**: Hard to maintain large programs
- **Update challenges**: Must replace entire program

### Multi-Program Benefits

1. **Modularity**: Each program handles one task
2. **Reusability**: Share programs across deployments
3. **Hot Updates**: Replace individual programs without disruption
4. **Complexity Management**: Stay under verifier limits

---

## 18.2 Tail Calls

### How Tail Calls Work

Tail calls allow one BPF program to call another, replacing itself:

```
Program A ──┬──► tail_call(B) ──► Program B runs
            │                     (A's context passed)
            └──► (A terminates)
```

```clojure
;; Create tail call map
(def prog-array
  {:type :prog_array
   :key-type :u32
   :value-type :prog-fd
   :max-entries 8})

;; Install programs in array
(defn setup-tail-calls []
  (bpf/map-update prog-array 0 (:fd protocol-parser))
  (bpf/map-update prog-array 1 (:fd tcp-handler))
  (bpf/map-update prog-array 2 (:fd udp-handler))
  (bpf/map-update prog-array 3 (:fd icmp-handler)))

;; Tail call from dispatcher
(def dispatcher-program
  [;; Parse protocol
   [(bpf/load-mem :b :r1 :r2 23)]  ; IP protocol
   [(bpf/mov-reg :r2 (bpf/map-ref prog-array))]
   [(bpf/call (bpf/helper :tail_call))]
   ;; Fall through if tail call fails
   [(bpf/mov :r0 2)]  ; XDP_PASS
   [(bpf/exit)]])
```

### Tail Call Limitations

1. **No return**: Called program never returns to caller
2. **Depth limit**: Maximum 33 tail calls in chain
3. **Same program type**: Can only tail call same type
4. **Context preserved**: Called program gets same ctx

### Tail Call Use Cases

| Use Case | Benefit |
|----------|---------|
| Protocol dispatch | Route to protocol-specific handler |
| Modular processing | Break large logic into stages |
| Extensibility | Add handlers without changing dispatcher |
| Size management | Stay under complexity limits |

---

## 18.3 Program Chaining with Shared State

### Shared Map Pattern

Multiple programs share state through maps:

```clojure
;; Shared state map
(def shared-state
  {:type :hash
   :key-type :u64      ; Flow ID
   :value-type [:struct
                {:stage :u8
                 :flags :u8
                 :data [16 :u8]}]
   :max-entries 10000})

;; Stage 1: Parser
(def parser-program
  [;; Parse packet, extract flow ID
   ;; ...
   ;; Store initial state
   [(bpf/mov-reg :r2 (bpf/map-ref shared-state))]
   ;; Update state with parsed data
   ;; Tail call to stage 2
   [(bpf/tail-call prog-array 1)]])

;; Stage 2: Validator
(def validator-program
  [;; Look up state from stage 1
   [(bpf/mov-reg :r2 (bpf/map-ref shared-state))]
   [(bpf/call (bpf/helper :map_lookup_elem))]
   ;; Validate and update stage
   ;; Tail call to stage 3
   [(bpf/tail-call prog-array 2)]])
```

### State Passing Techniques

1. **Per-flow state**: Hash map keyed by flow ID
2. **Per-packet state**: Array map indexed by CPU
3. **Scratch space**: Percpu array for temporary data

```clojure
;; Per-CPU scratch space
(def scratch
  {:type :percpu_array
   :key-type :u32
   :value-type [256 :u8]
   :max-entries 1})

;; Write to scratch
[(bpf/mov :r1 0)]
[(bpf/mov-reg :r2 (bpf/map-ref scratch))]
[(bpf/call (bpf/helper :map_lookup_elem))]
[(bpf/jmp-imm :jeq :r0 0 :exit)]
;; Store data at r0 (scratch pointer)
[(bpf/store-mem :dw :r0 0 :r6)]  ; Store value
```

---

## 18.4 Composable Program Architecture

### The Pipeline Pattern

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Parser  │───►│ Validate │───►│ Process  │───►│  Action  │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │
     └───────────────┴───────────────┴───────────────┘
                           │
                    ┌──────────────┐
                    │ Shared State │
                    │    (Maps)    │
                    └──────────────┘
```

```clojure
(defn create-pipeline [stages]
  "Create a BPF pipeline from stage specifications"
  (let [prog-array (bpf/create-map {:type :prog_array
                                    :max-entries (count stages)})
        shared-state (bpf/create-map {:type :percpu_hash
                                      :max-entries 10000})]
    ;; Load each stage
    (doseq [[idx stage] (map-indexed vector stages)]
      (let [prog (bpf/load-program
                   (wrap-stage stage idx (dec (count stages))))]
        (bpf/map-update prog-array idx (:fd prog))))

    {:prog-array prog-array
     :shared-state shared-state
     :stage-count (count stages)}))

(defn wrap-stage [stage idx last-idx]
  "Wrap a stage with state lookup and tail call"
  (concat
    ;; Lookup shared state
    [[(bpf/mov :r1 0)]
     [(bpf/mov-reg :r2 (bpf/map-ref 'shared-state))]
     [(bpf/call (bpf/helper :map_lookup_elem))]]
    ;; Stage logic
    stage
    ;; Tail call to next stage (if not last)
    (when (< idx last-idx)
      [[(bpf/mov-reg :r2 (bpf/map-ref 'prog-array))]
       [(bpf/mov :r3 (inc idx))]
       [(bpf/call (bpf/helper :tail_call))]])))
```

### The Plugin Pattern

Allow dynamic addition of handlers:

```clojure
(def plugin-registry
  {:type :prog_array
   :max-entries 64})

(defn register-plugin [slot-id program]
  "Register a plugin in the specified slot"
  (bpf/map-update plugin-registry slot-id (:fd program)))

(defn unregister-plugin [slot-id]
  "Remove a plugin from slot"
  (bpf/map-delete plugin-registry slot-id))

;; Dispatcher iterates through plugins
(def plugin-dispatcher
  [;; Try each plugin slot
   [(bpf/mov :r6 0)]  ; slot counter
   [:loop]
   [(bpf/jmp-imm :jge :r6 64 :done)]
   [(bpf/mov-reg :r2 (bpf/map-ref plugin-registry))]
   [(bpf/mov-reg :r3 :r6)]
   [(bpf/call (bpf/helper :tail_call))]
   ;; Tail call failed (no plugin), try next
   [(bpf/add :r6 1)]
   [(bpf/jmp :loop)]
   [:done]
   [(bpf/mov :r0 0)]
   [(bpf/exit)]])
```

---

## 18.5 Coordination Through Maps

### Signaling Between Programs

```clojure
;; Signal map for inter-program communication
(def signals
  {:type :array
   :key-type :u32
   :value-type :u64
   :max-entries 16})

(def signal-types
  {:pause 0
   :resume 1
   :reload 2
   :shutdown 3})

;; Check signal in BPF program
(def signal-check
  [[(bpf/mov :r1 0)]  ; Signal slot
   [(bpf/mov-reg :r2 (bpf/map-ref signals))]
   [(bpf/call (bpf/helper :map_lookup_elem))]
   [(bpf/jmp-imm :jeq :r0 0 :no-signal)]
   [(bpf/load-mem :dw :r1 :r0 0)]
   [(bpf/jmp-imm :jeq :r1 0 :no-signal)]  ; PAUSE
   [(bpf/mov :r0 0)]  ; Return early
   [(bpf/exit)]
   [:no-signal]])

;; Send signal from userspace
(defn send-signal [signal-type]
  (bpf/map-update signals 0 (get signal-types signal-type)))
```

### Versioned Configuration

```clojure
;; Config with version tracking
(def config-map
  {:type :array
   :value-type [:struct
                {:version :u64
                 :rate-limit :u32
                 :flags :u32
                 :data [24 :u8]}]
   :max-entries 1})

;; BPF program checks version
(def versioned-config-access
  [;; Load config
   [(bpf/mov :r1 0)]
   [(bpf/mov-reg :r2 (bpf/map-ref config-map))]
   [(bpf/call (bpf/helper :map_lookup_elem))]
   [(bpf/jmp-imm :jeq :r0 0 :use-defaults)]

   ;; Check version (stored in r7)
   [(bpf/load-mem :dw :r1 :r0 0)]  ; version field
   [(bpf/jmp-reg :jne :r1 :r7 :reload-config)]

   ;; Use cached config
   [(bpf/jmp :continue)]

   [:reload-config]
   ;; Version changed, reload config into registers
   [(bpf/mov-reg :r7 :r1)]  ; Save new version
   [(bpf/load-mem :w :r8 :r0 8)]   ; rate-limit
   [(bpf/load-mem :w :r9 :r0 12)]  ; flags

   [:continue]
   ;; Use r8, r9 for config values
   ])

;; Userspace: atomic config update
(defn update-config [new-config]
  (let [current (bpf/map-lookup config-map 0)
        new-version (inc (:version current))]
    (bpf/map-update config-map 0
                    (assoc new-config :version new-version))))
```

---

## 18.6 Hot Updates

### Atomic Program Replacement

```clojure
(defn atomic-replace-program [prog-array slot new-program]
  "Atomically replace program in slot"
  ;; Load new program
  (let [new-prog (bpf/load-program new-program)]
    ;; Atomic update to prog_array
    (bpf/map-update prog-array slot (:fd new-prog))
    ;; Old program continues until all references released
    new-prog))

(defn hot-update-handler [slot new-handler]
  "Hot update a handler with zero downtime"
  (println (format "Updating slot %d..." slot))
  (let [old-fd (bpf/map-lookup prog-array slot)
        new-prog (atomic-replace-program prog-array slot new-handler)]
    (println (format "Slot %d updated: fd %d -> %d"
                     slot old-fd (:fd new-prog)))
    new-prog))
```

### Gradual Rollout

```clojure
(def rollout-config
  {:type :array
   :value-type [:struct
                {:new-program-pct :u32   ; 0-100
                 :random-seed :u64}]
   :max-entries 1})

;; Dispatcher with gradual rollout
(def gradual-rollout-dispatcher
  [;; Get rollout config
   [(bpf/mov :r1 0)]
   [(bpf/mov-reg :r2 (bpf/map-ref rollout-config))]
   [(bpf/call (bpf/helper :map_lookup_elem))]
   [(bpf/jmp-imm :jeq :r0 0 :use-old)]

   ;; Get random value (simplified)
   [(bpf/call (bpf/helper :get_prandom_u32))]
   [(bpf/mod :r0 100)]  ; 0-99

   ;; Compare with rollout percentage
   [(bpf/load-mem :w :r1 :r0 0)]  ; new-program-pct
   [(bpf/jmp-reg :jlt :r0 :r1 :use-new)]

   [:use-old]
   [(bpf/tail-call prog-array 0)]  ; Old program
   [(bpf/jmp :fallback)]

   [:use-new]
   [(bpf/tail-call prog-array 1)]  ; New program

   [:fallback]
   [(bpf/mov :r0 0)]
   [(bpf/exit)]])

;; Userspace: gradually increase rollout
(defn gradual-rollout [duration-sec]
  (dotimes [pct 101]
    (bpf/map-update rollout-config 0 {:new-program-pct pct})
    (Thread/sleep (/ (* duration-sec 1000) 100))
    (println (format "Rollout: %d%%" pct))))
```

---

## 18.7 Debugging Multi-Program Systems

### Tracing Tail Calls

```clojure
(def trace-map
  {:type :percpu_array
   :value-type [:struct
                {:call-chain [8 :u32]
                 :depth :u32}]
   :max-entries 1})

;; Add tracing to each stage
(defn add-call-trace [program stage-id]
  (concat
    ;; Record this stage in trace
    [[(bpf/mov :r1 0)]
     [(bpf/mov-reg :r2 (bpf/map-ref trace-map))]
     [(bpf/call (bpf/helper :map_lookup_elem))]
     [(bpf/jmp-imm :jeq :r0 0 :skip-trace)]
     ;; Load depth
     [(bpf/load-mem :w :r1 :r0 32)]  ; depth offset
     ;; Store stage-id at depth
     [(bpf/mov :r2 stage-id)]
     [(bpf/atomic-add :w :r0 :r1 0)]  ; call-chain[depth]
     ;; Increment depth
     [(bpf/atomic-add :w :r0 1 32)]   ; depth++
     [:skip-trace]]
    program))

;; Read trace from userspace
(defn get-call-trace []
  (let [traces (bpf/map-lookup-percpu trace-map 0)]
    (for [trace traces]
      (take (:depth trace) (:call-chain trace)))))
```

### Performance Monitoring

```clojure
(def stage-latency
  {:type :percpu_array
   :value-type [:struct
                {:start-ns :u64
                 :total-ns :u64
                 :count :u64}]
   :max-entries 8})  ; One per stage

(defn wrap-with-timing [program stage-id]
  (concat
    ;; Record start time
    [[(bpf/call (bpf/helper :ktime_get_ns))]
     [(bpf/mov-reg :r6 :r0)]  ; Save start time
     [(bpf/mov :r1 stage-id)]
     [(bpf/mov-reg :r2 (bpf/map-ref stage-latency))]
     [(bpf/call (bpf/helper :map_lookup_elem))]
     [(bpf/jmp-imm :jeq :r0 0 :skip-start)]
     [(bpf/store-mem :dw :r0 0 :r6)]  ; start-ns
     [:skip-start]]
    program
    ;; Record end time and update stats
    [[(bpf/call (bpf/helper :ktime_get_ns))]
     [(bpf/sub-reg :r0 :r6)]  ; elapsed = now - start
     [(bpf/mov :r1 stage-id)]
     [(bpf/mov-reg :r2 (bpf/map-ref stage-latency))]
     [(bpf/call (bpf/helper :map_lookup_elem))]
     [(bpf/jmp-imm :jeq :r0 0 :skip-end)]
     [(bpf/atomic-add :dw :r0 :r6 8)]   ; total-ns += elapsed
     [(bpf/atomic-add :dw :r0 1 16)]    ; count++
     [:skip-end]]))

(defn get-stage-latencies []
  (for [stage-id (range 8)]
    (let [percpu-data (bpf/map-lookup-percpu stage-latency stage-id)
          total-ns (reduce + (map :total-ns percpu-data))
          total-count (reduce + (map :count percpu-data))]
      {:stage stage-id
       :avg-ns (if (pos? total-count)
                 (/ total-ns total-count)
                 0)
       :count total-count})))
```

---

## Labs

### Lab 18.1: Protocol Dispatcher

Build a multi-protocol packet handler using tail calls.

[Go to Lab 18.1](labs/lab-18-1-protocol-dispatcher.md)

### Lab 18.2: Pipeline Architecture

Implement a multi-stage processing pipeline with shared state.

[Go to Lab 18.2](labs/lab-18-2-pipeline-architecture.md)

### Lab 18.3: Hot Update System

Create a zero-downtime update system for BPF programs.

[Go to Lab 18.3](labs/lab-18-3-hot-updates.md)

---

## Key Takeaways

1. **Tail Calls**: Enable modular program design within complexity limits
2. **Shared State**: Maps provide communication between programs
3. **Composability**: Build complex systems from simple components
4. **Hot Updates**: Replace programs without service interruption
5. **Versioning**: Track configuration changes for cache invalidation
6. **Debugging**: Add tracing and timing for observability

## References

- [BPF Tail Calls](https://docs.cilium.io/en/stable/bpf/#tail-calls)
- [BPF Program Chaining](https://www.kernel.org/doc/html/latest/bpf/bpf_prog_run.html)
- [XDP Multi-Program](https://github.com/xdp-project/xdp-tools)
