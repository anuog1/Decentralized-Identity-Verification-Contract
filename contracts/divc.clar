;; Decentralized Identity Verification Contract
;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-TRUST-LEVEL (err u103))
(define-constant ERR-INVALID-PROVIDER (err u104))
(define-constant ERR-EXPIRED-VERIFICATION (err u105))


;; Trust levels - from lowest (1) to highest (5)
(define-constant TRUST-LEVEL-1 u1)
(define-constant TRUST-LEVEL-2 u2)
(define-constant TRUST-LEVEL-3 u3)
(define-constant TRUST-LEVEL-4 u4)
(define-constant TRUST-LEVEL-5 u5)


;; Data maps


;; Map of identity providers with their trust scores
(define-map identity-providers
 { provider-id: (string-ascii 50) }
 {
   name: (string-ascii 50),
   trust-score: uint,
   active: bool
 }
)


;; Map of user identities
(define-map user-identities
 { user: principal }
 {
   registered: bool,
   verification-status: bool,
   trust-level: uint,
   provider-id: (string-ascii 50),
   verification-hash: (buff 32),  ;; Hash of verification data - actual data stored off-chain
   verification-timestamp: uint,
   expiration-timestamp: uint
 }
)
