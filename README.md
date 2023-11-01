## CHALLENGE

Construct and setup a distributed system consisting of at least two servers and a client which allows the following:

The client should be able to share a secret using a secret sharing scheme with the servers.
The client should be able to retrieve and reconstruct its secret from the servers.
The servers should be able to refresh all stored client secret shares without client interaction.
This should be done under the following constraints:

No server knows the client's secret in plain at any point in time.
The server code must be written in Rust.
You must demonstrate the ability to deploy the servers. Either virtually on the same machine e.g. in Docker containers, or at a cloud provider.
The communication between all parties must be "secure".
Any front-end considerations of the client are not important for this challenge. What is important is that the servers can run on two different hosts (virtual or not) and interact with each other and the client securely.

For the secret sharing scheme you may use additive (or XOR) secret sharing, Shamir secret sharing or any other scheme you find fitting. Feel free to use libraries for this if it helps.

When it comes to refreshing; there are many advanced ways of carrying out such refreshing. However, any simple approach that re-randomizes existing shares is sufficient for this challenge.

---

## SOLUTION

Starting solving the challenge after reading it completely and attentively. I consider the challenge statement to be complete and self-sufficient, due to the non-interactive nature of it, yet in the context of the solution for the challenge I allow myself interpreting it as I see fit and reduce if necessary to the formal definition that makes sense to me, while technically satisfying the requirements and providing necessary deliverables. Outside the context of the solution for the challenge, I believe all details should be discussed, clarified and agreed upon in a design doc, which should happen before the implementation even starts.

### SHORTCUTS

- This project will never reach production, that's why I allow following shortcuts
- The main purpose of this solution is educational (it will never reach prod)
- The security principles are shown as principles, not prod-ready solutioms
- The Elliptic Curve math uses 32-bit modulus (it will never reach prod)
  - The same math still works out for properly chosen parameters
- Diffe-Hellman Key Exchange: uses 32-bit modulus (trivially "hackable")
  - But the principle remains the same (discrete logarithm problem)
  - For prod-like setup I would use:
    - 2048-bit prime and 
    - 256-bit random numbers
- The Secret is a 32-bit unsigned integer (represented as a hex string)
- The "trusted setup" is available
  - Each server's public key is known to all other servers
  - Can be enforced in prod-like env using certificates
- The ownership of the client's secret is based on valid signature
  - Secret is stored/retrieved only with a valid signature from the same key
- No usage of libraries (this solution serves educational purposes)
  - no `async` Rust (easy to go async, not so easy to go back)
  - no Tokio for IO & concurrency (spawning a few threads is enough here)
  - no crypto libs (reminder: educational purpose of the solution)
    - manual impl of DHKE with 32-bit modulus (without HKDF)
      - OK
    - manual impl of ECC with 32-bit curve (found with SageMath)
      - overkill: `i128` overflows at elliptic curve arithmetics
      - approach with `BigInt` attempted, and failed miserably
        - feature-rich, but really cumbersome API
        - significant performance penalty even for basic workloads
        - consulted with existing Rust implementation
          - way to much overhead for a homework
          - cutting looses quckly to avoid sinked costs fallacy
      - cutting this corver for the sake of my sanity, context and time

### TOPICS

* Secret sharing
  - Additive (XOR) secret sharing between N=2 servers
    - Potentially scalable to required number of servers
    - Client recovers the secret using all N shares ("N out of N")
  - Client's secret is never recoverable on any of the servers
* Refresh secret shares
  - Not complete sure what the functional goal of this is
    - But as long as shares are updated (refreshed)
    - and secret is still recoverable
    - then I consider it as done ("I allow myself interpreting it as I see fit ...")
  - The client's secret remains unchanged
  - Servers agree on "the mask" to XOR the shares with
    - For N=2 it is trivial
    - For larger N distributed consensus algorithm (e.g. PAXOS) can be used
  - The client's secret stays recoverable the same way as before
  - There are no client interaction for shares refresh
* Secure communications
  - Both client-server and server-server
  - Based on extremely simplified DHKE (see "Shortcuts")
  - To mitigate MitM-attach on DHKE: "trusted setup"
    - Each client & server holds a private key
    - Handshake messages (DHKE) are all:
      - signed by the sender
      - verified by the receiver
    - Once shared secret is agreed upon:
      - encrypted payload is signed & verified
    - Not implemented (see shortcut on elliptic curve arithmetics)

### HANDSHAKE (DHKE)

#### CLIENT

```
--- connet to the server
--- generate random 32-bit int A
>>> send G^A mod M (32-bit int)
<<< recv G^B mod M (32-bit int) = X
--- key= X^A mod M (32-bit int)
--- generate random 32-bit int T
>>> send T (encrypted with key)
<<< recv K (decrypted with key)
--- check that K==T-1
--- close the connection if not
(session handshake completed)

/--- (not implemented: see shortcut about elliptic curve arithmetics)
| >>> send current timestamp signed with private key
| <<< receive the same from the server and verify
| --- if not verified: reply with error frame 
| --- and then drop the connection
| >>> send OK frame to the server
| (server identity is verified at this point)
\---
```

#### SERVER

```
--- accept connection
<<< recv G^B mod M (32-bit int) = X
--- generate random 32-bit int A
>>> send G^A mod M (32-bit int)
--- key= X^A mod M (32-bit int)
<<< recv T (decrypted with key)
--- K=T-1
>>> send K (encrypted with key)
(session handshake completed)

/--- (not implemented: see shortcut about elliptic curve arithmetics)
| <<< receive signed timestamp, verify signature
| --- if not verified: reply with error frame 
| --- and then drop the connection
| >>> send the same to the client
| <<< receive OK frame from the client
| (client identity is verified at this point)
\---
```

### TRANSPORT

After the handshake, all communications between client and server are encrypted using the shared secret `key`. For the sake of simplicity (and to some some time for the impl) it is going to be simply rolling XOR (each 32 bits of the stream are XOR'ed with 32 bits of the key for encryption/decryption). It coule have been AES-256 in CBC mode (with 256-bit key derived from shared 2048-bit secret provide by DHKE) in "the real world", outside of educational challenge context.

#### FRAME

```
idx: u32, // nonce of the message
tag: u32, // message tag (see below)
msg: u32, // message 'content'
key: u32, // public key
sig: u64, // signature over `crc32(idx || tag || msg || ext)`
ext: u32, // extra (e.g. error code)
sum: u32, // crc32 of all fields above
```

#### MESSAGE

```
tag=1: `msg` containst secret share (u32)
tag=2: `msg` contains public key (u32)

tag=200: OK (`msg` is b"OKAY", `ext` is zero)
tag=400: client problem (`msg` is b"NOPE", error code in `ext`)
tag=500: server problem (`msg` is b"NOPE", error code in `ext`)

## 'HELLO' message, handshake
tag=255: `msg` contains random u32
# Client sends HELLO with a random number and a valid signature
# Server responds with HELLO, also a number and a signature
```

### THREAT ANALYSIS

Imagining that the solution is using properly selected:
- parameters for Diffie-Hellman Key Exchange (2048-bit modulus and 256-bit random exponents)
- parameters for the Elliptice Curve cryptography (Ed25519 curve with 256-bit public key)
- parameters for per-session symmetric encryption (AES-256 with PKCS7 padding in CBC mode)

#### THREATS

- Quantum-safety: efficient solution for prime factorizaton (Shor's algorithm)
  - solution: switch to DHKE over Elliptic Curves
- Replay-attack: nonce (`idx`), checksum and signature for each frame
  - seems like good enough setup for detecting attempts to tamper with messages
- Man-in-the-Middle: client must verify the signature of the HELLO message
  - trusted setup for sharing and rotating public keys

---

## RUN

Start server 1 (note the `sync` flag):

`cargo run --bin server AAAAAAAA 10001 127.0.0.1:10002 sync`

Start server 2 (no `sync`):

`cargo run --bin server BBBBBBBB 10002 127.0.0.1:10001`

Store the secret:

`cargo run --bin client 12345678 127.0.0.1:10001 127.0.0.1:10002 set CAFEBABE`

Retrieve the secret (note changing shares every time the secret is retrieved):

`cargo run --bin client 12345678 127.0.0.1:10001 127.0.0.1:10002 get`

Refreshing of secret shares happens after each retrieval of the secret shares by the client. Each consecutive retrieval will result in a new set shares, that yet will produce the necessary secret when combined properly (XOR'ed). The refresh is initiated by the server and does not require any interactions between a client and the server. The single designated server (with "sync" mode passed as an argument) is responsible for triggering refresh for all remaining servers. In case of odd number of servers N, N-1 shares get updated (all except the "sync"-enabled one); in case of even numbers number of servers - all shares get updated. In real world something like two-phase commit would be necessary to ensure smooth refresh, but just for the sake of simplicity, I'm going to make a single roundrip from the "sync" server to all remaining ones ("one-phase commit").

Such un-coordinated propagation leads to a race condition, when different shares might from servers before and/or after refresh completed, thus making recovered secret invalid. There are multiple strategies to mitigate this but I think the most elegant and simple one is to keep track of all versions of the shares and serve them in the order of refresh. The overhead is to either run a distributed consensus (PAXOS) or a leadership election (Raft) algorithm to determine which single server triggers refresh, or move it to the operational domain and during servers deployment ensure only single instance has "sync" flag enabled. Implementing PAXOS/Raft is way out of scope, but (shameles plug) I actually did implement [PAXOS](https://github.com/sergey-melnychuk/uppercut/blob/develop/examples/paxos.rs) in a very simple demonstrative example.

Both `client` and `server` are platform-specific binaries, thus they can be packaged and run with any packaging tool & approach. I consider the deployment part covered by this, not spending any more time on docker/k8s/you-name-it config.

---

At this point I consider base impl points covered, and won't update this document any more.

I am also rejecting significant amount of "polishing" for the code, just for the sake of time.

The final submission will be at the state "it works and can be run with singe command". Enough is enugh :)

List of things skipped:
- proper logging & maybe metrics
- proper error propagation and handling
- proper CLI with `clap`
- proper unit-testing (basic one only)
- proper system-testing (little to no)
- signature/checksum validation
- isolating logical blocks into modules
- blocking/non-blocking code separation
