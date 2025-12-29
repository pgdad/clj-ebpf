# Plan: High-Level Declarative Macros

## 1. Feature Description
To reduce boilerplate and make `clj-ebpf` more "Clojure-like" for scripting and application development, we will introduce a suite of high-level macros. These macros will allow users to define BPF programs and map specifications declaratively at the top level, and simplify the "load-attach-run-cleanup" lifecycle.

## 2. Implementation Details

### 2.1 New Namespace: `src/clj_ebpf/macros.clj`
Create a new namespace to house these macros to avoid cluttering `core.clj`. These macros should be re-exported by `clj-ebpf.core` for ease of use.

### 2.2 Macro Definitions

#### `defprogram`
Defines a named var containing the **assembled bytecode** and metadata. It performs `dsl/assemble` at macro expansion time (if possible) or runtime, returning a map compatible with `load-program`.

```clojure
(defprogram my-packet-filter
  :type :xdp
  :license "GPL"
  :opts {:log-level 2}
  :body [
    (xdp/parse-ethernet ...)
    ...
  ])

;; Usage:
;; (bpf/load-program my-packet-filter)
```

#### `defmap-spec`
Defines a reusable map specification.

```clojure
(defmap-spec my-hash-map
  :type :hash
  :key-size 4
  :value-size 8
  :max-entries 1024)

;; Usage:
;; (bpf/create-map my-hash-map)
```

#### `with-bpf-script` (or `quick-start`)
A "god macro" for quick scripts, tutorials, and REPL experiments. It handles the entire lifecycle of maps and programs.

```clojure
(with-bpf-script
  {:maps [m1 my-hash-map]           ; Create map 'm1' from spec
   :progs [p1 my-packet-filter]     ; Load program 'p1' from spec
   :attach [{:prog p1               ; Attach p1
             :type :xdp
             :target "eth0"}]}
  ;; Body executed while attached
  (println "Running BPF...")
  (Thread/sleep 5000))
  ;; Automatically detaches, unloads programs, and closes maps
```

## 3. Integration
- Update `clj-ebpf.core` to require and refer these macros.
- Ensure `dsl` namespaces are available or required correctly within the macro expansions.

## 4. Testing Strategy

### 4.1 Unit Tests (`test/clj_ebpf/macros_test.clj`)
- Test `defprogram` expansion and resulting data structure.
- Test `defmap-spec` expansion.
- Test `with-bpf-script` lifecycle (using mocks to avoid real kernel interactions).

### 4.2 Integration Tests
- Real-world test: Define a simple XDP program using `defprogram`, run it with `with-bpf-script` on `lo` interface.

## 5. Examples
Create `examples/macro_dsl.clj`:
```clojure
(ns examples.macro-dsl
  (:require [clj-ebpf.core :as bpf]
            [clj-ebpf.macros :refer [defprogram defmap-spec with-bpf-script]]
            [clj-ebpf.dsl.xdp :as xdp]))

(defmap-spec counter-map
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 1)

(defprogram filter-prog
  :type :xdp
  :body [(xdp/pass)])

(defn -main []
  (with-bpf-script
    {:maps [m counter-map]
     :progs [p filter-prog]
     :attach [{:prog p :type :xdp :target "lo"}]}
    (println "Running on loopback...")))
```

## 6. Documentation
- Create `docs/guides/macros.md`.
- Update `README.md` to show the new, cleaner syntax.
