# Show HN: I built a post-quantum Double Ratchet SDK in Rust with Flutter FFI

Hey HN,

I wanted to share PQ-Aura, a hybrid post-quantum cryptographic SDK I’ve been working on, written in Rust with Flutter bindings.

Historically, end-to-end encrypted messaging has relied on the Double Ratchet algorithm (X3DH + noise protocol) using classical elliptic curves like Curve25519. With Shor's algorithm on the horizon, these classical key exchanges are vulnerable.

PQ-Aura implements a hybrid post-quantum approach:
1. It combines classical Curve25519 with Kyber (ML-KEM-1024) for key encapsulation.
2. The cryptographic core is written in pure Rust (for performance and safety guarantees).
3. It exposes Flutter FFI bindings so mobile developers can integrate post-quantum E2EE with zero crypto boilerplate.

Under the hood:
- The server (built in Axum with SQLite persistence) manages PreKeys and handles cryptographic handshakes asynchronously.
- The hybrid design ensures that even if Kyber is found to have implementation vulnerabilities, the security defaults back to the classical Curve25519 layer (and vice versa).

I've also just implemented a dual-licensing setup (GPLv3 for open-source / commercial licensing for enterprise apps) and a licensing webhook server.

Repository: https://github.com/peter14l/pq-dr  (or your Hugging Face Space / website link)

I'd love to hear your thoughts on:
- Best practices for hybrid key exchanges in real-world mobile environments.
- Performance implications of post-quantum KEMs on mobile devices over high-latency connections.
- Your general feedback on the API layout and developer experience.

Thanks!

---

# Alternative: Short Comment for Link Submissions

I built PQ-Aura to solve a specific problem: making post-quantum encryption easy to implement for mobile developers. 

It implements a hybrid scheme combining classical Curve25519 with Kyber (ML-KEM-1024). If Kyber fails, the classical layer protects the message; if the classical layer is cracked by a quantum computer, Kyber holds the line.

The core library is written in Rust, and I’ve packaged it with Flutter FFI bindings so it can run cross-platform on iOS and Android without needing platform-specific rewrite. The repository also includes a lightweight Axum-based key exchange server.

I'd appreciate any feedback on the cryptographic hybrid integration or the developer ergonomics of the Flutter API!
