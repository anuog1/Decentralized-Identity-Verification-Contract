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
;; Map to track verification requirements for different services/applications
(define-map verification-requirements
 { service-id: (string-ascii 50) }
 {
   required-trust-level: uint,
   required-providers: (list 10 (string-ascii 50)),
   kyc-required: bool,
   aml-required: bool
 }
)


;; Contract owner
(define-data-var contract-owner principal tx-sender)


;; Public functions


;; Register a new user in the system
(define-public (register-user)
 (let
   ((user tx-sender))
   (asserts! (not (default-to false (get registered (map-get? user-identities { user: user })))) ERR-ALREADY-REGISTERED)
  
   (map-set user-identities
     { user: user }
     {
       registered: true,
       verification-status: false,
       trust-level: u0,
       provider-id: "",
       verification-hash: 0x,
       verification-timestamp: u0,
       expiration-timestamp: u0
     }
   )
   (ok true)
 )
)


;; Add a new identity provider (only contract owner)
(define-public (add-provider (provider-id (string-ascii 50)) (name (string-ascii 50)) (trust-score uint))
 (begin
   (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
   (asserts! (and (>= trust-score TRUST-LEVEL-1) (<= trust-score TRUST-LEVEL-5)) ERR-INVALID-TRUST-LEVEL)
  
   (map-set identity-providers
     { provider-id: provider-id }
     {
       name: name,
       trust-score: trust-score,
       active: true
     }
   )
   (ok true)
 )
)
;; Update provider status (only contract owner)
(define-public (update-provider-status (provider-id (string-ascii 50)) (active bool))
 (begin
   (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
   (asserts! (is-some (map-get? identity-providers { provider-id: provider-id })) ERR-INVALID-PROVIDER)
  
   (let ((provider (unwrap-panic (map-get? identity-providers { provider-id: provider-id }))))
     (map-set identity-providers
       { provider-id: provider-id }
       {
         name: (get name provider),
         trust-score: (get trust-score provider),
         active: active
       }
     )
   )
   (ok true)
 )
)


;; Verify a user's identity (called by authorized provider)
;; In a real implementation, provider would be authenticated via multi-sig or other mechanism
(define-public (verify-user (user principal) (provider-id (string-ascii 50)) (verification-hash (buff 32)) (expiration-blocks uint))
 (let
   (
     (provider (unwrap! (map-get? identity-providers { provider-id: provider-id }) ERR-INVALID-PROVIDER))
     (user-identity (unwrap! (map-get? user-identities { user: user }) ERR-NOT-REGISTERED))
     (current-block-height block-height)
     (expiration-timestamp (+ current-block-height expiration-blocks))
   )
  
   ;; Check provider is active
   (asserts! (get active provider) ERR-INVALID-PROVIDER)
  
;; Update user's identity verification
   (map-set user-identities
     { user: user }
     {
       registered: true,
       verification-status: true,
       trust-level: (get trust-score provider),
       provider-id: provider-id,
       verification-hash: verification-hash,
       verification-timestamp: current-block-height,
       expiration-timestamp: expiration-timestamp
     }
   )
   (ok true)
 )
)
;; Set verification requirements for a service/application (only contract owner)
(define-public (set-verification-requirements
                (service-id (string-ascii 50))
                (required-trust-level uint)
                (required-providers (list 10 (string-ascii 50)))
                (kyc-required bool)
                (aml-required bool))
 (begin
   (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
   (asserts! (and (>= required-trust-level TRUST-LEVEL-1) (<= required-trust-level TRUST-LEVEL-5)) ERR-INVALID-TRUST-LEVEL)
  
   (map-set verification-requirements
     { service-id: service-id }
     {
       required-trust-level: required-trust-level,
       required-providers: required-providers,
       kyc-required: kyc-required,
       aml-required: aml-required
     }
   )
   (ok true)
 )
