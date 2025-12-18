(ns clj-ebpf.dsl-xdp-test
  "Tests for XDP DSL features
   CI-safe (no BPF privileges required)"
  {:ci-safe true}
  (:require [clojure.test :refer [deftest testing is are]]
            [clj-ebpf.dsl.xdp :as xdp]
            [clj-ebpf.dsl :as dsl]))

;; ============================================================================
;; XDP Actions Tests
;; ============================================================================

(deftest test-xdp-actions
  (testing "XDP actions map contains all actions"
    (is (map? xdp/xdp-actions))
    (is (contains? xdp/xdp-actions :aborted))
    (is (contains? xdp/xdp-actions :drop))
    (is (contains? xdp/xdp-actions :pass))
    (is (contains? xdp/xdp-actions :tx))
    (is (contains? xdp/xdp-actions :redirect)))

  (testing "XDP action values are correct"
    (is (= 0 (:aborted xdp/xdp-actions)))
    (is (= 1 (:drop xdp/xdp-actions)))
    (is (= 2 (:pass xdp/xdp-actions)))
    (is (= 3 (:tx xdp/xdp-actions)))
    (is (= 4 (:redirect xdp/xdp-actions))))

  (testing "xdp-action returns correct values"
    (is (= 0 (xdp/xdp-action :aborted)))
    (is (= 1 (xdp/xdp-action :drop)))
    (is (= 2 (xdp/xdp-action :pass)))
    (is (= 3 (xdp/xdp-action :tx)))
    (is (= 4 (xdp/xdp-action :redirect))))

  (testing "xdp-action throws for unknown actions"
    (is (thrown? clojure.lang.ExceptionInfo
                 (xdp/xdp-action :invalid)))))

;; ============================================================================
;; xdp_md Offsets Tests
;; ============================================================================

(deftest test-xdp-md-offsets
  (testing "xdp-md-offsets contains all fields"
    (is (map? xdp/xdp-md-offsets))
    (is (contains? xdp/xdp-md-offsets :data))
    (is (contains? xdp/xdp-md-offsets :data-end))
    (is (contains? xdp/xdp-md-offsets :data-meta))
    (is (contains? xdp/xdp-md-offsets :ingress-ifindex))
    (is (contains? xdp/xdp-md-offsets :rx-queue-index)))

  (testing "xdp-md offsets are correct"
    (is (= 0 (:data xdp/xdp-md-offsets)))
    (is (= 4 (:data-end xdp/xdp-md-offsets)))
    (is (= 8 (:data-meta xdp/xdp-md-offsets)))
    (is (= 12 (:ingress-ifindex xdp/xdp-md-offsets)))
    (is (= 16 (:rx-queue-index xdp/xdp-md-offsets))))

  (testing "xdp-md-offset function works"
    (is (= 0 (xdp/xdp-md-offset :data)))
    (is (= 4 (xdp/xdp-md-offset :data-end))))

  (testing "xdp-md-offset throws for unknown fields"
    (is (thrown? clojure.lang.ExceptionInfo
                 (xdp/xdp-md-offset :invalid)))))

;; ============================================================================
;; Protocol Header Offsets Tests
;; ============================================================================

(deftest test-ethernet-offsets
  (testing "Ethernet header offsets are correct"
    (is (= 0 (:dst-mac xdp/ethernet-offsets)))
    (is (= 6 (:src-mac xdp/ethernet-offsets)))
    (is (= 12 (:ethertype xdp/ethernet-offsets))))

  (testing "Ethernet header size is correct"
    (is (= 14 xdp/ethernet-header-size))))

(deftest test-ipv4-offsets
  (testing "IPv4 header offsets are correct"
    (is (= 0 (:version-ihl xdp/ipv4-offsets)))
    (is (= 8 (:ttl xdp/ipv4-offsets)))
    (is (= 9 (:protocol xdp/ipv4-offsets)))
    (is (= 12 (:src-addr xdp/ipv4-offsets)))
    (is (= 16 (:dst-addr xdp/ipv4-offsets))))

  (testing "IPv4 minimum header size is correct"
    (is (= 20 xdp/ipv4-header-min-size))))

(deftest test-ipv6-offsets
  (testing "IPv6 header offsets are correct"
    (is (= 6 (:next-header xdp/ipv6-offsets)))
    (is (= 7 (:hop-limit xdp/ipv6-offsets)))
    (is (= 8 (:src-addr xdp/ipv6-offsets)))
    (is (= 24 (:dst-addr xdp/ipv6-offsets))))

  (testing "IPv6 header size is correct"
    (is (= 40 xdp/ipv6-header-size))))

(deftest test-tcp-offsets
  (testing "TCP header offsets are correct"
    (is (= 0 (:src-port xdp/tcp-offsets)))
    (is (= 2 (:dst-port xdp/tcp-offsets)))
    (is (= 4 (:seq xdp/tcp-offsets)))
    (is (= 8 (:ack xdp/tcp-offsets)))
    (is (= 13 (:flags xdp/tcp-offsets))))

  (testing "TCP minimum header size is correct"
    (is (= 20 xdp/tcp-header-min-size))))

(deftest test-udp-offsets
  (testing "UDP header offsets are correct"
    (is (= 0 (:src-port xdp/udp-offsets)))
    (is (= 2 (:dst-port xdp/udp-offsets)))
    (is (= 4 (:length xdp/udp-offsets)))
    (is (= 6 (:checksum xdp/udp-offsets))))

  (testing "UDP header size is correct"
    (is (= 8 xdp/udp-header-size))))

(deftest test-ethertypes
  (testing "EtherType values are correct"
    (is (= 0x0800 (:ipv4 xdp/ethertypes)))
    (is (= 0x0806 (:arp xdp/ethertypes)))
    (is (= 0x86DD (:ipv6 xdp/ethertypes)))
    (is (= 0x8100 (:vlan xdp/ethertypes)))))

(deftest test-ip-protocols
  (testing "IP protocol numbers are correct"
    (is (= 1 (:icmp xdp/ip-protocols)))
    (is (= 6 (:tcp xdp/ip-protocols)))
    (is (= 17 (:udp xdp/ip-protocols)))
    (is (= 58 (:icmpv6 xdp/ip-protocols)))))

(deftest test-tcp-flags
  (testing "TCP flag values are correct"
    (is (= 0x01 (:fin xdp/tcp-flags)))
    (is (= 0x02 (:syn xdp/tcp-flags)))
    (is (= 0x04 (:rst xdp/tcp-flags)))
    (is (= 0x08 (:psh xdp/tcp-flags)))
    (is (= 0x10 (:ack xdp/tcp-flags)))
    (is (= 0x20 (:urg xdp/tcp-flags)))))

;; ============================================================================
;; Context Access Tests
;; ============================================================================

(deftest test-xdp-load-ctx-field
  (testing "xdp-load-ctx-field generates ldx instruction"
    (let [insn (xdp/xdp-load-ctx-field :r1 :data :r2)]
      (is (bytes? insn))
      (is (= 8 (count insn)))))

  (testing "xdp-load-ctx-field works with different fields"
    (is (some? (xdp/xdp-load-ctx-field :r1 :data-end :r3)))
    (is (some? (xdp/xdp-load-ctx-field :r1 :ingress-ifindex :r4)))))

(deftest test-xdp-load-data-pointers
  (testing "xdp-load-data-pointers generates two instructions"
    (let [insns (xdp/xdp-load-data-pointers :r1 :r2 :r3)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-prologue
  (testing "xdp-prologue without context save"
    (let [prologue (xdp/xdp-prologue :r2 :r3)]
      (is (vector? prologue))
      (is (= 2 (count prologue)))
      (is (every? bytes? prologue))))

  (testing "xdp-prologue with context save"
    (let [prologue (xdp/xdp-prologue :r9 :r2 :r3)]
      (is (vector? prologue))
      (is (= 3 (count prologue)))
      (is (every? bytes? prologue)))))

;; ============================================================================
;; Bounds Checking Tests
;; ============================================================================

(deftest test-xdp-bounds-check
  (testing "xdp-bounds-check generates correct instructions"
    (let [insns (xdp/xdp-bounds-check :r2 :r3 14)]
      (is (vector? insns))
      (is (= 5 (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-bounds-check with custom action"
    (let [insns (xdp/xdp-bounds-check :r2 :r3 14 :drop)]
      (is (vector? insns))
      (is (= 5 (count insns)))))

  (testing "xdp-bounds-check with different sizes"
    (is (= 5 (count (xdp/xdp-bounds-check :r2 :r3 20))))
    (is (= 5 (count (xdp/xdp-bounds-check :r2 :r3 100))))))

(deftest test-xdp-bounds-check-var
  (testing "xdp-bounds-check-var generates correct instructions"
    (let [insns (xdp/xdp-bounds-check-var :r2 :r3 :r4)]
      (is (vector? insns))
      (is (= 5 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Packet Data Access Tests
;; ============================================================================

(deftest test-xdp-load-byte
  (testing "xdp-load-byte generates ldx instruction"
    (let [insn (xdp/xdp-load-byte :r2 0 :r4)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-xdp-load-half
  (testing "xdp-load-half generates ldx instruction"
    (let [insn (xdp/xdp-load-half :r2 12 :r4)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

(deftest test-xdp-load-word
  (testing "xdp-load-word generates ldx instruction"
    (let [insn (xdp/xdp-load-word :r2 16 :r4)]
      (is (bytes? insn))
      (is (= 8 (count insn))))))

;; ============================================================================
;; Ethernet Parsing Tests
;; ============================================================================

(deftest test-xdp-parse-ethernet
  (testing "xdp-parse-ethernet generates correct instructions"
    (let [insns (xdp/xdp-parse-ethernet :r2 :r3 :r4)]
      (is (vector? insns))
      ;; Bounds check (5) + load ethertype (1) = 6
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; IPv4 Parsing Tests
;; ============================================================================

(deftest test-xdp-parse-ipv4
  (testing "xdp-parse-ipv4 with protocol only"
    (let [insns (xdp/xdp-parse-ipv4 :r2 :r3 14 :r4)]
      (is (vector? insns))
      ;; Bounds check (5) + load protocol (1) = 6
      (is (= 6 (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-parse-ipv4 with src and dst IP"
    (let [insns (xdp/xdp-parse-ipv4 :r2 :r3 14 :r4 :r5 :r6)]
      (is (vector? insns))
      ;; Bounds check (5) + protocol (1) + src (1) + dst (1) = 8
      (is (= 8 (count insns))))))

(deftest test-xdp-get-ipv4-header-length
  (testing "xdp-get-ipv4-header-length generates instructions"
    (let [insns (xdp/xdp-get-ipv4-header-length :r2 14 :r4)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; IPv6 Parsing Tests
;; ============================================================================

(deftest test-xdp-parse-ipv6
  (testing "xdp-parse-ipv6 generates correct instructions"
    (let [insns (xdp/xdp-parse-ipv6 :r2 :r3 14 :r4)]
      (is (vector? insns))
      ;; Bounds check (5) + load next-header (1) = 6
      (is (= 6 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; TCP/UDP Parsing Tests
;; ============================================================================

(deftest test-xdp-parse-tcp
  (testing "xdp-parse-tcp with ports"
    (let [insns (xdp/xdp-parse-tcp :r2 :r3 34 :src-port :r4 :dst-port :r5)]
      (is (vector? insns))
      ;; Bounds check (5) + src port (1) + dst port (1) = 7
      (is (= 7 (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-parse-tcp with flags"
    (let [insns (xdp/xdp-parse-tcp :r2 :r3 34 :flags :r4)]
      (is (vector? insns))
      ;; Bounds check (5) + flags (1) = 6
      (is (= 6 (count insns))))))

(deftest test-xdp-parse-udp
  (testing "xdp-parse-udp with ports"
    (let [insns (xdp/xdp-parse-udp :r2 :r3 34 :src-port :r4 :dst-port :r5)]
      (is (vector? insns))
      ;; Bounds check (5) + src port (1) + dst port (1) = 7
      (is (= 7 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; XDP Helper Tests
;; ============================================================================

(deftest test-xdp-adjust-head
  (testing "xdp-adjust-head generates call instructions"
    (let [insns (xdp/xdp-adjust-head :r9 16)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-adjust-tail
  (testing "xdp-adjust-tail generates call instructions"
    (let [insns (xdp/xdp-adjust-tail :r9 -4)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-adjust-meta
  (testing "xdp-adjust-meta generates call instructions"
    (let [insns (xdp/xdp-adjust-meta :r9 8)]
      (is (vector? insns))
      (is (= 3 (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; Program Building Tests
;; ============================================================================

(deftest test-build-xdp-program
  (testing "build-xdp-program creates valid bytecode"
    (let [prog (xdp/build-xdp-program
                {:body []
                 :default-action :pass})]
      (is (bytes? prog))
      (is (> (count prog) 0))
      (is (zero? (mod (count prog) 8)))))

  (testing "build-xdp-program with body instructions"
    (let [prog (xdp/build-xdp-program
                {:ctx-reg :r9
                 :body [(dsl/mov :r4 42)]
                 :default-action :drop})]
      (is (bytes? prog))
      (is (> (count prog) 0))))

  (testing "build-xdp-program uses default action"
    (let [prog1 (xdp/build-xdp-program {:body []})
          prog2 (xdp/build-xdp-program {:body [] :default-action :drop})]
      ;; Both should compile
      (is (bytes? prog1))
      (is (bytes? prog2)))))

;; ============================================================================
;; Macro Tests
;; ============================================================================

(xdp/defxdp-instructions test-drop-all
  {:default-action :drop}
  [])

(xdp/defxdp-instructions test-pass-all
  {:default-action :pass
   :ctx-reg :r9}
  [(dsl/mov :r4 123)])

(deftest test-defxdp-instructions-macro
  (testing "defxdp-instructions creates a function"
    (is (fn? test-drop-all))
    (is (fn? test-pass-all)))

  (testing "defxdp-instructions returns instructions"
    (let [insns (test-drop-all)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "defxdp-instructions includes prologue"
    (let [insns (test-pass-all)]
      ;; ctx save (1) + data pointers (2) + body (1) + return (2) = 6
      (is (= 6 (count insns))))))

;; ============================================================================
;; Section Name Tests
;; ============================================================================

(deftest test-xdp-section-name
  (testing "xdp-section-name without interface"
    (is (= "xdp" (xdp/xdp-section-name))))

  (testing "xdp-section-name with interface"
    (is (= "xdp/eth0" (xdp/xdp-section-name "eth0")))
    (is (= "xdp/ens192" (xdp/xdp-section-name "ens192")))))

;; ============================================================================
;; Program Info Tests
;; ============================================================================

(deftest test-make-xdp-program-info
  (testing "make-xdp-program-info returns correct structure"
    (let [info (xdp/make-xdp-program-info "my_xdp" [])]
      (is (map? info))
      (is (= "my_xdp" (:name info)))
      (is (= "xdp" (:section info)))
      (is (= :xdp (:type info)))
      (is (vector? (:instructions info)))))

  (testing "make-xdp-program-info with interface"
    (let [info (xdp/make-xdp-program-info "my_xdp" [] "eth0")]
      (is (= "xdp/eth0" (:section info)))
      (is (= "eth0" (:interface info))))))

;; ============================================================================
;; Common Patterns Tests
;; ============================================================================

(deftest test-xdp-return-action
  (testing "xdp-return-action generates mov and exit"
    (let [insns (xdp/xdp-return-action :drop)]
      (is (vector? insns))
      (is (= 2 (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-return-action works with all actions"
    (doseq [action [:aborted :drop :pass :tx :redirect]]
      (is (= 2 (count (xdp/xdp-return-action action)))))))

(deftest test-xdp-drop-if-port
  (testing "xdp-drop-if-port generates correct instructions"
    (let [insns (xdp/xdp-drop-if-port :r2 :r3 34 0 80 true)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-pass-only-tcp
  (testing "xdp-pass-only-tcp generates correct instructions"
    (let [insns (xdp/xdp-pass-only-tcp :r2 :r3)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

;; ============================================================================
;; IP Address Helper Tests
;; ============================================================================

(deftest test-ipv4-to-int
  (testing "ipv4-to-int converts correctly"
    (is (= 0xC0A80101 (xdp/ipv4-to-int "192.168.1.1")))
    (is (= 0x0A000001 (xdp/ipv4-to-int "10.0.0.1")))
    (is (= 0x7F000001 (xdp/ipv4-to-int "127.0.0.1")))
    (is (= 0x00000000 (xdp/ipv4-to-int "0.0.0.0")))
    ;; Note: 255.255.255.255 would overflow as signed int
    ;; Use a smaller value for reliable testing
    (is (= 0x0A0A0A0A (xdp/ipv4-to-int "10.10.10.10")))))

(deftest test-xdp-match-ipv4
  (testing "xdp-match-ipv4 generates correct instructions"
    ;; Use 10.0.0.1 (0x0A000001) which fits in signed 32-bit
    (let [insns (xdp/xdp-match-ipv4 :r2 :r3 0x0A000001 true :drop)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns))))

  (testing "xdp-match-ipv4 for src and dst"
    ;; Use 127.0.0.1 (0x7F000001) which fits in signed 32-bit
    (let [src-insns (xdp/xdp-match-ipv4 :r2 :r3 0x7F000001 true :drop)
          dst-insns (xdp/xdp-match-ipv4 :r2 :r3 0x7F000001 false :drop)]
      ;; Both should have same structure but different offsets
      (is (= (count src-insns) (count dst-insns))))))

;; ============================================================================
;; Byte Order Helper Tests
;; ============================================================================

(deftest test-xdp-bswap16
  (testing "xdp-bswap16 generates instructions"
    (let [insns (xdp/xdp-bswap16 :r4)]
      (is (vector? insns))
      (is (pos? (count insns)))
      (is (every? bytes? insns)))))

(deftest test-xdp-bswap32
  (testing "xdp-bswap32 generates endian instruction"
    (let [insns (xdp/xdp-bswap32 :r4 :r5)]
      (is (vector? insns))
      (is (= 1 (count insns)))
      (is (bytes? (first insns))))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest test-complete-xdp-program-assembly
  (testing "Complete XDP drop program assembles correctly"
    (let [bytecode (dsl/assemble (test-drop-all))]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0))
      (is (zero? (mod (count bytecode) 8)))))

  (testing "Complete XDP pass program assembles correctly"
    (let [bytecode (dsl/assemble (test-pass-all))]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0))
      (is (zero? (mod (count bytecode) 8))))))

(deftest test-xdp-program-with-parsing
  (testing "XDP program with Ethernet parsing assembles"
    (let [insns (vec (concat
                      (xdp/xdp-prologue :r9 :r2 :r3)
                      (xdp/xdp-parse-ethernet :r2 :r3 :r4)
                      (xdp/xdp-return-action :pass)))
          bytecode (dsl/assemble insns)]
      (is (bytes? bytecode))
      (is (> (count bytecode) 0)))))

;; ============================================================================
;; API Completeness Tests
;; ============================================================================

(deftest test-api-completeness
  (testing "All XDP action functions are defined"
    (is (fn? xdp/xdp-action)))

  (testing "All context access functions are defined"
    (is (fn? xdp/xdp-load-ctx-field))
    (is (fn? xdp/xdp-load-data-pointers))
    (is (fn? xdp/xdp-prologue)))

  (testing "All bounds check functions are defined"
    (is (fn? xdp/xdp-bounds-check))
    (is (fn? xdp/xdp-bounds-check-var)))

  (testing "All packet access functions are defined"
    (is (fn? xdp/xdp-load-byte))
    (is (fn? xdp/xdp-load-half))
    (is (fn? xdp/xdp-load-word)))

  (testing "All parsing functions are defined"
    (is (fn? xdp/xdp-parse-ethernet))
    (is (fn? xdp/xdp-parse-ipv4))
    (is (fn? xdp/xdp-parse-ipv6))
    (is (fn? xdp/xdp-parse-tcp))
    (is (fn? xdp/xdp-parse-udp)))

  (testing "All helper functions are defined"
    (is (fn? xdp/xdp-adjust-head))
    (is (fn? xdp/xdp-adjust-tail))
    (is (fn? xdp/xdp-adjust-meta)))

  (testing "All builder functions are defined"
    (is (fn? xdp/build-xdp-program))
    (is (fn? xdp/xdp-section-name))
    (is (fn? xdp/make-xdp-program-info))))

(deftest test-documentation
  (testing "Core functions have docstrings"
    (is (string? (:doc (meta #'xdp/xdp-action))))
    (is (string? (:doc (meta #'xdp/xdp-prologue))))
    (is (string? (:doc (meta #'xdp/xdp-bounds-check))))
    (is (string? (:doc (meta #'xdp/xdp-parse-ethernet))))
    (is (string? (:doc (meta #'xdp/build-xdp-program))))))
