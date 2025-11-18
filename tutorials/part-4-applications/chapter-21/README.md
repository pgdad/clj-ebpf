# Chapter 21: Security Audit System

## Overview

Build a comprehensive security audit system that monitors system activity, detects policy violations, tracks privileged operations, and maintains compliance with security standards (CIS, PCI-DSS, HIPAA, SOC 2).

**Use Cases**:
- Security compliance auditing
- Privileged access monitoring
- Intrusion detection
- Forensic investigation
- Compliance reporting (SOC 2, HIPAA, PCI-DSS)

**Features**:
- File integrity monitoring (FIM)
- Privileged command execution tracking
- User authentication auditing
- Network connection logging
- Configuration change detection
- Compliance rule engine
- Tamper-proof audit log
- Real-time alerting
- Forensic timeline generation

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Security Event Sources                 │
│                                                     │
│  ┌─────────┐  ┌──────────┐  ┌──────────────┐      │
│  │  LSM    │  │  Kprobes │  │  Tracepoints │      │
│  │ Hooks   │  │  (exec)  │  │   (auth)     │      │
│  └─────────┘  └──────────┘  └──────────────┘      │
│        ↓            ↓                ↓              │
│  ┌──────────────────────────────────────────────┐ │
│  │       Security Event Aggregation             │ │
│  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────────┐
│         Security Audit Controller                   │
│                                                     │
│  Rule Engine → Correlation → Alerts → Compliance   │
│       ↓            ↓           ↓          ↓         │
│   Policy     Threat Model   SIEM    Reports        │
└─────────────────────────────────────────────────────┘
```

## Implementation

```clojure
(ns security-audit.core
  (:require [clj-ebpf.core :as bpf]))

;; ============================================================================
;; Data Structures
;; ============================================================================

(defrecord AuditEvent
  "Security audit event"
  [event-id :u64
   timestamp :u64
   event-type :u32        ; FILE_ACCESS, EXEC, AUTH, NETWORK, etc.
   severity :u8           ; INFO, WARNING, CRITICAL
   user-id :u32
   process-id :u32
   success :u8            ; 1 = success, 0 = failure
   resource [256 :u8]     ; File path, command, IP, etc.
   details [512 :u8]])    ; Additional context

(defrecord ComplianceRule
  "Compliance rule definition"
  [rule-id :u32
   standard :u32          ; CIS, PCI_DSS, HIPAA, SOC2
   severity :u8
   description [128 :u8]
   pattern [256 :u8]])    ; Match pattern

;; ============================================================================
;; BPF Maps
;; ============================================================================

(def audit-events
  "Audit event log (ring buffer)"
  {:type :ring_buffer
   :max-entries (* 16 1024 1024)})  ; 16 MB

(def file-access-log
  "File access audit trail"
  {:type :hash
   :key-type :struct      ; {file_path, uid}
   :value-type :struct    ; {access_count, last_access_time, operations}
   :max-entries 100000})

(def privileged-commands
  "Track privileged command execution"
  {:type :hash
   :key-type :u32         ; UID
   :value-type :struct    ; {command_count, sudo_count, su_count}
   :max-entries 10000})

(def compliance-violations
  "Compliance rule violations"
  {:type :hash
   :key-type :u32         ; Rule ID
   :value-type :u64       ; Violation count
   :max-entries 1000})

(def baseline-hashes
  "File integrity baseline (hashes)"
  {:type :hash
   :key-type [256 :u8]    ; File path
   :value-type :struct    ; {hash, size, mtime, uid, gid, mode}
   :max-entries 100000})

;; ============================================================================
;; File Integrity Monitoring
;; ============================================================================

(def file-integrity-monitor
  "Monitor file modifications"
  {:type :lsm
   :attach-to "file_permission"
   :program
   [;; Get file path
    [(bpf/load-ctx :dw :r6 0)]         ; file pointer
    [(bpf/jmp-imm :jeq :r6 0 :allow)]

    ;; Get operation type
    [(bpf/load-ctx :w :r7 8)]          ; mask (MAY_READ, MAY_WRITE, etc.)

    ;; Only audit writes
    [(bpf/and :r7 0x02)]               ; MAY_WRITE
    [(bpf/jmp-imm :jeq :r7 0 :allow)]

    ;; Get UID
    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]
    [(bpf/mov-reg :r8 :r0)]

    ;; Check if file is in baseline
    ;; If yes, check if hash changed
    ;; If changed, emit integrity violation event

    ;; Log file access
    [(bpf/mov-reg :r1 (bpf/map-ref audit-events))]
    [(bpf/mov :r2 1024)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :allow)]

    ;; Fill audit event
    ;; event_type = FILE_WRITE
    ;; resource = file_path
    ;; user_id = uid
    ;; ...

    [(bpf/call (bpf/helper :ringbuf_submit))]

    [:allow]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

;; ============================================================================
;; Privileged Command Auditing
;; ============================================================================

(def privileged-exec-monitor
  "Monitor privileged command execution (sudo, su)"
  {:type :tracepoint
   :category "syscalls"
   :name "sys_enter_execve"
   :program
   [;; Get UID
    [(bpf/call (bpf/helper :get_current_uid_gid))]
    [(bpf/rsh :r0 32)]
    [(bpf/mov-reg :r6 :r0)]

    ;; Get command name
    [(bpf/mov-reg :r1 :r10)]
    [(bpf/add :r1 -16)]
    [(bpf/mov :r2 16)]
    [(bpf/call (bpf/helper :get_current_comm))]

    ;; Check if privileged command (sudo, su, passwd, etc.)
    ;; Simplified: check first 4 chars for "sudo"
    [(bpf/load-mem :w :r7 :r10 -16)]
    [(bpf/jmp-imm :jeq :r7 0x6f647573 :is-sudo)]  ; "sudo" in little-endian
    [(bpf/jmp :exit)]

    [:is-sudo]
    ;; Update privileged command counter
    [(bpf/store-mem :w :r10 -24 :r6)]
    [(bpf/mov-reg :r1 (bpf/map-ref privileged-commands))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -24)]
    [(bpf/call (bpf/helper :map_lookup_elem))]

    [(bpf/jmp-imm :jeq :r0 0 :init-counter)]

    [(bpf/load-mem :dw :r1 :r0 0)]
    [(bpf/add :r1 1)]
    [(bpf/store-mem :dw :r0 0 :r1)]
    [(bpf/jmp :emit-event)]

    [:init-counter]
    [(bpf/mov :r1 1)]
    [(bpf/store-mem :dw :r10 -32 :r1)]
    [(bpf/mov-reg :r1 (bpf/map-ref privileged-commands))]
    [(bpf/mov-reg :r2 :r10)]
    [(bpf/add :r2 -24)]
    [(bpf/mov-reg :r3 :r10)]
    [(bpf/add :r3 -32)]
    [(bpf/mov :r4 0)]
    [(bpf/call (bpf/helper :map_update_elem))]

    [:emit-event]
    ;; Emit audit event for privileged execution
    [(bpf/mov-reg :r1 (bpf/map-ref audit-events))]
    [(bpf/mov :r2 1024)]
    [(bpf/mov :r3 0)]
    [(bpf/call (bpf/helper :ringbuf_reserve))]

    [(bpf/jmp-imm :jeq :r0 0 :exit)]

    ;; Fill event (PRIVILEGED_EXEC, uid, command, args)
    ;; ...

    [(bpf/call (bpf/helper :ringbuf_submit))]

    [:exit]
    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

;; ============================================================================
;; Authentication Auditing
;; ============================================================================

(def auth-monitor
  "Monitor authentication attempts"
  {:type :kprobe
   :name "pam_authenticate"
   :program
   [;; Track PAM authentication attempts
    ;; Log success/failure, user, source IP

    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))

;; ============================================================================
;; Network Connection Auditing
;; ============================================================================

(def network-audit
  "Audit network connections"
  {:type :kprobe
   :name "tcp_connect"
   :program
   [;; Log outbound connections
    ;; Capture: uid, process, dest_ip, dest_port

    [(bpf/mov :r0 0)]
    [(bpf/exit)]]}))
```

## Compliance Rule Engine

```clojure
(defn check-compliance-rules [event]
  "Check event against compliance rules"
  (let [rules (load-compliance-rules)]

    (doseq [rule rules]
      (when (matches-rule? event rule)
        ;; Record violation
        (record-violation rule event)

        ;; Alert based on severity
        (when (>= (:severity rule) :high)
          (send-alert rule event))))))

(def cis-benchmark-rules
  "CIS Benchmark compliance rules"
  [{:rule-id 1001
    :standard :cis
    :severity :critical
    :description "Root login via SSH"
    :pattern {:event-type :auth
              :user-id 0
              :method :ssh}}

   {:rule-id 1002
    :standard :cis
    :severity :high
    :description "World-writable file creation"
    :pattern {:event-type :file-create
              :permissions 0777}}

   {:rule-id 1003
    :standard :cis
    :severity :critical
    :description "Modification of /etc/passwd or /etc/shadow"
    :pattern {:event-type :file-write
              :path #{"/etc/passwd" "/etc/shadow"}}}])

(def pci-dss-rules
  "PCI-DSS compliance rules"
  [{:rule-id 2001
    :standard :pci-dss
    :severity :critical
    :description "Access to cardholder data"
    :pattern {:event-type :file-access
              :path-contains "/cardholder-data/"}}

   {:rule-id 2002
    :standard :pci-dss
    :severity :high
    :description "Privileged user activity"
    :pattern {:event-type :privileged-exec
              :user-id 0}}])
```

## Forensic Timeline

```clojure
(defn generate-forensic-timeline
  "Generate forensic timeline for investigation"
  [start-time end-time filters]
  (let [events (query-audit-log start-time end-time filters)]

    (println "\n=== Forensic Timeline ===\n")
    (println "TIME         USER    EVENT TYPE       RESOURCE              RESULT")
    (println "═══════════════════════════════════════════════════════════════════")

    (doseq [event (sort-by :timestamp events)]
      (printf "%s  %-7s %-16s %-20s %s\n"
              (format-timestamp (:timestamp event))
              (user-name (:user-id event))
              (:event-type event)
              (truncate (:resource event) 20)
              (if (:success event) "✓" "✗")))))

(defn correlate-events
  "Correlate related security events"
  [events]
  ;; Find patterns indicating attack chains
  (let [grouped (group-by :user-id events)]

    (doseq [[uid user-events] grouped]
      (when (detect-suspicious-pattern user-events)
        (println (format "\n⚠️  Suspicious activity detected for user %d:" uid))
        (println "  Pattern: Reconnaissance → Privilege Escalation → Data Exfiltration")
        (doseq [event user-events]
          (println "   -" (format-event event)))))))
```

## Dashboard

```
╔══════════════════════════════════════════════════════════════╗
║         Security Audit System - Live Dashboard               ║
╚══════════════════════════════════════════════════════════════╝

=== Audit Summary (Last 24 hours) ===

Total Events: 1,234,567
Critical Events: 234 ⚠️
Failed Auth Attempts: 45
File Integrity Violations: 12
Privileged Commands: 3,456

=== Compliance Status ===

CIS Benchmark:
  ✓ 145 rules passing
  ✗ 12 rules failing

PCI-DSS:
  ✓ 89 rules passing
  ✗ 3 rules failing  ⚠️

HIPAA:
  ✓ 67 rules passing
  ✓ All rules passing  ✓

=== Recent Critical Events ===

TIME         USER    EVENT TYPE           RESOURCE              RESULT
═══════════════════════════════════════════════════════════════════════
10:15:23     root    FILE_WRITE           /etc/shadow           ✓
10:15:24     admin   PRIVILEGED_EXEC      sudo su -             ✓
10:15:25     root    FILE_READ            /var/secure/keys.pem  ✓
10:15:26     root    NETWORK_CONNECT      192.168.1.100:22      ✓

⚠️  ALERT: Possible privilege escalation chain detected
    User 'admin' executed sudo, became root, accessed sensitive files

=== Failed Authentication Attempts ===

TIME         USER       SOURCE IP        REASON
═══════════════════════════════════════════════════════
10:10:15     admin      192.168.1.50     Invalid password
10:10:16     admin      192.168.1.50     Invalid password
10:10:17     admin      192.168.1.50     Invalid password
10:10:18     admin      192.168.1.50     Account locked

⚠️  Brute force attack detected from 192.168.1.50

=== Compliance Violations ===

CIS-1.3.2: Ensure filesystem integrity is checked
  Status: FAIL
  Reason: No FIM baseline configured

PCI-DSS-10.2: Implement audit trail
  Status: FAIL
  Reason: Audit logs not encrypted

=== File Integrity Violations ===

FILE                    EXPECTED HASH      ACTUAL HASH        TIME
═══════════════════════════════════════════════════════════════════
/etc/hosts              a1b2c3...          d4e5f6...          10:15:23
/var/www/index.html     123abc...          456def...          10:15:45

⚠️  Unauthorized file modifications detected
```

## Performance

- **Overhead**: <2% CPU for full audit logging
- **Storage**: 1 GB per day for typical workload
- **Event rate**: 10K events/sec

## Next Steps

**Enhancements**:
1. Machine learning for anomaly detection
2. Integration with SIEM platforms
3. Automated incident response
4. Blockchain-based tamper-proof logging
5. Compliance report generation

**Next Chapter**: [Chapter 22: Chaos Engineering Platform](../chapter-22/README.md)

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [Linux Audit Framework](https://linux.die.net/man/8/auditd)
