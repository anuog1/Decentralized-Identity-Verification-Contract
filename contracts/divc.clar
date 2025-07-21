;; Decentralized Identity Verification Contract

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-TRUST-LEVEL (err u103))
(define-constant ERR-INVALID-PROVIDER (err u104))
(define-constant ERR-EXPIRED-VERIFICATION (err u105))
(define-constant ERR-SERVICE-NOT-FOUND (err u106))
(define-constant ERR-VERIFICATION-FAILED (err u107))
(define-constant ERR-INSUFFICIENT-TRUST-LEVEL (err u108))
(define-constant ERR-PROVIDER-NOT-APPROVED (err u109))
(define-constant ERR-INVALID-EXPIRATION (err u110))
(define-constant ERR-INVALID-INPUT (err u111))

;; Trust levels - from lowest (1) to highest (5)
(define-constant TRUST-LEVEL-1 u1)
(define-constant TRUST-LEVEL-2 u2)
(define-constant TRUST-LEVEL-3 u3)
(define-constant TRUST-LEVEL-4 u4)
(define-constant TRUST-LEVEL-5 u5)

;; Minimum expiration blocks (1 day assuming 10-minute blocks)
(define-constant MIN-EXPIRATION-BLOCKS u144)

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
    (asserts! (> (len provider-id) u0) ERR-INVALID-INPUT)
    (asserts! (> (len name) u0) ERR-INVALID-INPUT)
   
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

;; Update provider trust score (only contract owner)
(define-public (update-provider-trust-score (provider-id (string-ascii 50)) (trust-score uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= trust-score TRUST-LEVEL-1) (<= trust-score TRUST-LEVEL-5)) ERR-INVALID-TRUST-LEVEL)
    (asserts! (is-some (map-get? identity-providers { provider-id: provider-id })) ERR-INVALID-PROVIDER)
   
    (let ((provider (unwrap-panic (map-get? identity-providers { provider-id: provider-id }))))
      (map-set identity-providers
        { provider-id: provider-id }
        {
          name: (get name provider),
          trust-score: trust-score,
          active: (get active provider)
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
    ;; Check minimum expiration time
    (asserts! (>= expiration-blocks MIN-EXPIRATION-BLOCKS) ERR-INVALID-EXPIRATION)
    ;; Validate verification hash is not empty
    (asserts! (not (is-eq verification-hash 0x)) ERR-INVALID-INPUT)
   
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
    (asserts! (> (len service-id) u0) ERR-INVALID-INPUT)
   
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
)

;; Check if a user meets verification requirements for a service
(define-public (check-verification (user principal) (service-id (string-ascii 50)))
  (let
    (
      (user-identity (unwrap! (map-get? user-identities { user: user }) ERR-NOT-REGISTERED))
      (requirements (unwrap! (map-get? verification-requirements { service-id: service-id }) ERR-SERVICE-NOT-FOUND))
      (current-block-height block-height)
    )
   
    ;; Check verification status
    (asserts! (get verification-status user-identity) ERR-VERIFICATION-FAILED)
   
    ;; Check if verification is expired
    (asserts! (<= current-block-height (get expiration-timestamp user-identity)) ERR-EXPIRED-VERIFICATION)
   
    ;; Check if user meets trust level
    (asserts! (>= (get trust-level user-identity) (get required-trust-level requirements)) ERR-INSUFFICIENT-TRUST-LEVEL)
   
    ;; Check if provider is in the required list (if non-empty)
    (if (> (len (get required-providers requirements)) u0)
        (asserts! (is-some (index-of (get required-providers requirements) (get provider-id user-identity))) ERR-PROVIDER-NOT-APPROVED)
        true
    )
       
    (ok true)
  )
)

;; Revoke user verification (only contract owner - for emergency situations)
(define-public (revoke-verification (user principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? user-identities { user: user })) ERR-NOT-REGISTERED)
   
    (let ((user-identity (unwrap-panic (map-get? user-identities { user: user }))))
      (map-set user-identities
        { user: user }
        {
          registered: (get registered user-identity),
          verification-status: false,
          trust-level: u0,
          provider-id: "",
          verification-hash: 0x,
          verification-timestamp: u0,
          expiration-timestamp: u0
        }
      )
    )
    (ok true)
  )
)

;; Read-only functions

;; Get user verification status
(define-read-only (get-user-verification-status (user principal))
  (let ((user-identity (map-get? user-identities { user: user })))
    (if (is-some user-identity)
        (let ((identity (unwrap-panic user-identity)))
          (if (and
                (get verification-status identity)
                (<= block-height (get expiration-timestamp identity))
              )
              (ok {
                verified: true,
                trust-level: (get trust-level identity),
                provider: (get provider-id identity),
                expiration: (get expiration-timestamp identity)
              })
              (ok {
                verified: false,
                trust-level: u0,
                provider: "",
                expiration: u0
              })
          )
        )
        (err ERR-NOT-REGISTERED)
    )
  )
)

;; Get service requirements
(define-read-only (get-service-requirements (service-id (string-ascii 50)))
  (ok (map-get? verification-requirements { service-id: service-id }))
)

;; Get provider information
(define-read-only (get-provider-info (provider-id (string-ascii 50)))
  (ok (map-get? identity-providers { provider-id: provider-id }))
)

;; Get contract owner
(define-read-only (get-contract-owner)
  (ok (var-get contract-owner))
)

;; Check if user is registered
(define-read-only (is-user-registered (user principal))
  (default-to false (get registered (map-get? user-identities { user: user })))
)

;; Get all user verification details (including expired)
(define-read-only (get-user-full-details (user principal))
  (ok (map-get? user-identities { user: user }))
)

;; Transfer contract ownership (only current owner)
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq new-owner tx-sender)) ERR-INVALID-INPUT)
    (var-set contract-owner new-owner)
    (ok true)
  )
)