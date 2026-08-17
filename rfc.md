## Pkarr: Public-key Addressable Resource Records

### Abstract

This document specifies Pkarr, a system for decentralized publishing and resolution of signed DNS-like packets. Pkarr enables self-issued Ed25519 public keys to function as sovereign, publicly addressable, and censorship-resistant top-level domains. It provides a streamlined integration between the Domain Name System and peer-to-peer overlay networks, creating a foundational layer for distributed discovery. By leveraging the battle-tested Mainline DHT for distribution, Pkarr offers a pragmatic path toward a more open and resilient web, where identity and service location are decoupled from central authorities. Optional extensions are defined for HTTP relay services, endpoint discovery via SVCB/HTTPS records, and TLS connections using Raw Public Keys.

### 1. Introduction

The pursuit of a sovereign, distributed, and open web faces several challenges, including distributed semantics for identity, distributed databases for verifiable data, and distributed discovery for locating that data. Pkarr addresses the most foundational of these: **Distributed Discovery**.

Pkarr provides a decentralized alternative to traditional DNS for naming and service discovery, where ownership and control of a name are derived from possession of a cryptographic key. This solves critical issues of unavailability, censorship, and de-platforming by allowing users to maintain a long-lasting identity and conveniently update resource records to point to different providers. The core system allows entities to publish signed DNS packets under their public key, which acts as a Top-Level Domain (TLD). These packets can be resolved by anyone via a distributed hash table (DHT). By building on proven technologies like the Mainline DHT and DNS, Pkarr achieves significant leverage with minimal new invention, providing a robust solution for mapping sovereign keys to network locations.

Optional specifications extend this core functionality to constrained environments like web browsers and enable secure, direct connections to services.

#### 1.1. Goals and Non-Goals

**Goals:**
*   Enable public keys to be used as resolvable, sovereign identifiers.
*   Provide a censorship-resistant method for publishing and discovering resource records.
*   Leverage existing, robust infrastructure (Mainline DHT, DNS) for immediate practicality and resilience.
*   Abstract over emerging solutions for distributed data and semantics, ensuring long-term relevance.

**Non-Goals:**
*   To be a general-purpose storage platform (records are ephemeral and size-limited).
*   To provide a real-time communication medium (extensive caching is inherent to the design).
*   To introduce scarcity or rent-seeking via human-readable names.

### 2. Terminology

*   **Public Key / Pkarr Key:** A 32-byte Ed25519 public key, serving as the root identifier for a Pkarr domain.
*   **Z-Base32:** A human-oriented base-32 encoding scheme [Z-Base32] used to represent the public key as a TLD-compatible string.
*   **SignedPacket:** The core data structure containing a DNS packet signed by the corresponding private key.
*   **Mainline DHT:** The Kademlia-based Distributed Hash Table [BEP0005] used as the primary storage and retrieval layer for SignedPackets.
*   **Relay:** An optional HTTP server that proxies DHT operations for clients that cannot participate in the DHT directly.
*   **Endpoint:** A network-accessible service (e.g., a web server) associated with a Pkarr domain.
*   **SVCB/HTTPS Record:** A DNS resource record type [RFC9460] used for service binding and endpoint discovery.
*   **Republisher:** An entity (e.g., a service provider) that periodically re-publishes a SignedPacket to the DHT to keep it alive.

### 3. Core Specification

#### 3.1. Domain Name Representation

A Pkarr domain is the z-base32 encoding of a 32-byte Ed25519 public key. This string is treated as a TLD compatible with DNS and URIs.

**Examples:**
*   Standalone Key: `o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy`
*   URI with Scheme: `pk:o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy`
*   Full URI: `https://foo.o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy`

Implementations MUST be able to parse the z-base32 encoded key from a URI authority/host component, with or without the `pk:` scheme prefix.

#### 3.2. SignedPacket Format

The `SignedPacket` is the fundamental unit of data, containing a DNS packet cryptographically bound to a public key and a timestamp.

##### 3.2.1. Canonical Encoding

The `SignedPacket` is serialized in the following format:

```
SignedPacket = public-key signature timestamp dns-packet

public-key  = 32 OCTET  ; Ed25519 public key
signature   = 64 OCTET  ; Ed25519 signature
timestamp   =  8 OCTET  ; Big-endian UNIX timestamp in microseconds
dns-packet  =  * OCTET  ; Compressed, encoded DNS answer packet (max ~1000 bytes)
```

##### 3.2.2. DNS Packet Requirements

The `dns-packet` field MUST be a valid DNS message in the format defined in [RFC1035], containing one or more answer resource records.
*   All resource records MUST be relative to the Pkarr domain (the public key). For example, a record for `foo` corresponds to the full name `foo.<z-base32-public-key>`.
*   The DNS packet SHOULD use compression [RFC1035, Section 4.1.4] to reduce size, but implementations MUST be able to parse uncompressed packets.

##### 3.2.3. Signing and Verification

The data to be signed is a bencoded [BEP0003] concatenation of the sequence number (timestamp) and the DNS packet.

```abnf
signable          = prefix dns-packet

prefix            = "3:seqi" timestamp "e1:v" dns-packet-length ":"
dns-packet        = * OCTET ; Compressed encoded DNS answer packet, less than 1000 bytes

timestamp         = 1*DIGIT ; Integer representing the timestamp
dns-packet-length = 1*DIGIT ; Integer representing the length of the encoded DNS packet
```

The `signature` is generated by signing the `signable` string using the Ed25519 private key corresponding to the `public-key`.

Upon receiving a `SignedPacket`, implementations MUST verify:
1.  The `timestamp` is more recent than any previously cached packet for the same public key.
2.  The `signature` is valid for the `signable` data and the `public-key`.
3.  The `dns-packet` can be parsed as a valid DNS message.

#### 3.3. DHT Publishing and Resolving

Pkarr uses the Mainline DHT with the mutable item extension [BEP0044] for storage and retrieval.

##### 3.3.1. Publishing a SignedPacket

To publish a `SignedPacket`, a client performs a DHT PUT operation with the following mapping:

| DHT PUT Argument (BEP0044) | SignedPacket Field      |
| -------------------------- | ----------------------- |
| `k` (public key)           | `public-key` (32 bytes) |
| `seq` (sequence number)    | `timestamp` (as integer)|
| `sig` (signature)          | `signature` (64 bytes)  |
| `v` (value)                | `dns-packet`            |

The `cas` and `salt` fields from BEP0044 are ignored and should not be used.

##### 3.3.2. Resolving a SignedPacket

To resolve a `SignedPacket` for a public key, a client performs a DHT GET operation.

| DHT GET Argument (BEP0044) | Value                               |
| -------------------------- | ----------------------------------- |
| `target`                   | `SHA1(public-key)` (20 bytes)       |
| `seq` (optional)           | `timestamp` of the latest known packet |

### 4. Relay Specification (Optional)

Relays are HTTP servers that proxy DHT operations for clients unable to use the DHT directly (e.g., in web browsers).

#### 4.1. API Overview

Relays SHOULD support HTTP/2 and SHOULD set appropriate CORS headers to allow access from web clients.
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, OPTIONS
```

#### 4.2. PUT - Publishing via Relay

##### 4.2.1. Request
```
PUT /:z-base32-encoded-key HTTP/2
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, OPTIONS
If-Match: <sequence-number>  ; Optional, for conditional put

<body>
```
The request body is a `RelayPayload` (see Section 4.4).

##### 4.2.2. Processing
Upon receiving a PUT request, the relay MUST:
1.  Construct the `signable` data as defined in Section 3.2.3.
2.  Verify the signature in the payload against the public key (derived from the URL path) and the `signable` data.
3.  Perform a DHT PUT operation as specified in Section 3.3.1, optionally using the `If-Match` header value as the `cas` parameter.
4.  Return an appropriate HTTP status code based on the outcome.

##### 4.2.3. Response Codes
*   `204 No Content`: Success.
*   `400 Bad Request`: Invalid public key, signature, or DNS packet.
*   `409 Conflict`: The provided sequence number is older than the current one (BEP0044 error 302).
*   `412 Precondition Failed`: The `If-Match` condition failed (BEP0044 error 301).
*   `413 Payload Too Large`: The payload exceeds ~1000 bytes.
*   `428 Precondition Required`: The relay requires an `If-Match` header to prevent conflicts.
*   `429 Too Many Requests`: Rate limiting applied.

#### 4.3. GET - Resolving via Relay

##### 4.3.1. Request
```
GET /:z-base32-encoded-key HTTP/2
If-Modified-Since: <http-date>  ; Optional
```

##### 4.3.2. Processing
Upon receiving a GET request, the relay MUST:
1.  Perform a DHT GET operation for the public key.
2.  If a `SignedPacket` is found, construct the `RelayPayload` and return it in the response body.
3.  Honor the `If-Modified-Since` header by comparing it to the packet's timestamp, returning `304 Not Modified` if applicable.

##### 4.3.3. Response
```
HTTP/2 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, OPTIONS
Content-Type: application/pkarr.org/relays#payload
Cache-Control: public, max-age=<ttl>
Last-Modified: <http-date>

<body>
```

- `Cache-Control` header would help browsers reduce their reliance on the relay, the `max-age` should be set to be the minimum `ttl` in the resource records in the packet or some minimum ttl chosen by the relay.
- `If-Modified-Since` can be sent by the client to avoid downloading packets they already have, when the relay responds with `304 Not Modified`.

#### 4.4. Relay Payload Format

The payload for relay requests and responses omits the public key, which is implied by the URL path.

```
RelayPayload = signature timestamp dns-packet

signature   = 64 OCTET  ; Ed25519 signature
timestamp   =  8 OCTET  ; Big-endian UNIX timestamp in microseconds
dns-packet  =  * OCTET  ; Compressed, encoded DNS answer packet
```

### 5. Endpoint Discovery (Optional)

Pkarr domains can advertise network endpoints using SVCB/HTTPS records [RFC9460]. This allows a client to discover how to connect to a service at a Pkarr domain (e.g., `https://<pkarr-key>`).

#### 5.1. Client-Side Resolution Algorithm

To resolve an endpoint for a Pkarr domain (`qname`):
1.  **Resolve SignedPacket:** Fetch the `SignedPacket` for the `qname`'s Pkarr key (the TLD).
2.  **Find HTTPS Records:** Extract all `HTTPS` resource records from the DNS packet whose name matches the `qname` or a relevant wildcard.
3.  **Sort and Prioritize:** Sort the `HTTPS` records by their `priority` field in ascending order. Records with the same priority SHOULD be shuffled for load balancing.
4.  **Iterate and Resolve:** For each record in sorted order:
    a.  If `target` is `.` (dot), the endpoint is the Pkarr domain itself. Use its `A`/`AAAA` records for IP addresses and the `HTTPS` parameters (e.g., `port`, `alpn`) for connection details.
    b.  If `target` is another Pkarr key, recursively resolve the `SignedPacket` for that key and restart from step 2 with the new key and the `target` as the new `qname`.
    c.  If `target` is a conventional domain name, resolve it using standard DNS mechanisms to obtain endpoint details.

#### 5.2. Server-Side Configuration

*   **Directly Accessible Servers:** SHOULD publish an `HTTPS` record with the `target` set to `.` and include `A`/`AAAA` records. The `HTTPS` record SHOULD specify parameters like `port` and `alpn`.
*   **Proxied Servers:** SHOULD publish an `HTTPS` record with the `target` set to the domain name of their reverse proxy or hosting provider.

#### 5.3. Legacy Browser Compatibility

For clients that cannot resolve Pkarr domains natively, at least one endpoint with a conventional ICANN domain name MUST be provided in the `HTTPS` record `target` field to ensure fallback connectivity.

### 6. TLS with Raw Public Keys (Optional)

Once an endpoint is resolved and is directly accessible via its Pkarr key, clients can establish a secure TLS connection using the Raw Public Keys (RPK) method [RFC7250].

#### 6.1. Supported Algorithms

As Pkarr keys are Ed25519 keys, the only supported `signature_algorithm` for TLS MUST be `ed25519 (0x0807)`.

#### 6.2. Client Implementation

Clients with full control over the TLS stack SHOULD use the endpoint's public key (from the `SignedPacket`) for RPK authentication. Clients using conventional TLS certificate validation can use the endpoint discovery process to find a domain-based fallback.

#### 6.3. Server Implementation

Servers MUST be configured to present their Raw Public Key (the Ed25519 public key) during the TLS handshake and to require client authentication using RPK if desired.

#### 6.4. Reverse Proxy Configuration

When a server is behind a reverse proxy:
1.  The proxy MUST be configured for TLS passthrough, not termination.
2.  The proxy SHOULD use a dedicated `port` and forward raw TCP traffic to the server.
3.  The server's `HTTPS` record MUST point to the proxy's address and dedicated port.

#### 6.5. Legacy Browser Compatibility

TLS with Raw Public Keys is not supported by legacy browsers. Servers MUST provide a domain-based endpoint (as per Section 5.3) with a valid X.509 certificate for these clients.

### 7. IANA Considerations

This document has no IANA actions.

### 8. Security Considerations

*   **Key Management:** The security of a Pkarr domain is entirely dependent on the secrecy of its private key. Loss or compromise of the private key leads to a full compromise of the domain.
*   **DHT Trust Model:** The DHT is a public, permissionless network. Clients must rigorously verify signatures on all retrieved `SignedPackets`.
*   **Relay Trust:** Relays are untrusted in the core security model. They cannot forge valid `SignedPackets` but they can censor, delay, or serve stale data. Use of multiple relays or direct DHT access is recommended for critical applications.
*   **Replay Attacks:** The sequence number (timestamp) prevents replay of old packets. Implementations MUST reject packets with non-increasing sequence numbers.
*   **RPK Security:** Using Raw Public Keys eliminates the need for a CA hierarchy but requires a secure channel to obtain the initial public key, which Pkarr provides via DHT and signature verification.

### 9. References

#### 9.1. Normative References
*   [BEP0005] Wang, L., "Mainline DHT Protocol", BitTorrent Enhancement Proposal 0005.
*   [BEP0044] Norberg, A., "DHT Mutable Items", BitTorrent Enhancement Proposal 0044.
*   [RFC1035] Mockapetris, P., "Domain names - implementation and specification", STD 13, RFC 1035.
*   [RFC9460] Schwartz, B., "Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)", RFC 9460.
*   [RFC7250] Wouters, P., "Using Raw Public Keys in Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)", RFC 7250.

#### 9.2. Informative References
*   [Z-Base32] Zooko Wilcox-O'Hearn, "Human-Oriented Base-32 Encoding".
*   [BEP0003] "The BitTorrent Protocol Specification", BitTorrent Enhancement Proposal 0003.

### Authors' Addresses

Nuh
nuh.dev
Email: nuh@nuh.dev
