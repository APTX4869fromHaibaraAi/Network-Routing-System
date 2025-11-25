# UDP Tunnel Protocol Specification

## Overview
This document defines the custom UDP tunnel protocol used for encapsulating IP packets between network access endpoints and routing servers.

## Packet Format

### Header Structure (32 bytes total: 16 byte header + 16 byte HMAC)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Type      |     Flags     |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Tunnel ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sequence Number                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Timestamp (ms)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      HMAC-SHA256 (16 bytes)                   |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Payload (IP Packet)                   |
|                              ...                              |
```

### Field Descriptions

- **Version** (1 byte): Protocol version, currently 0x01
- **Type** (1 byte): Message type
  - 0x01: DATA - Contains encapsulated IP packet
  - 0x02: KEEPALIVE - Tunnel keepalive message
  - 0x03: CONTROL - Control message
- **Flags** (1 byte): Bit flags
  - Bit 0: IPv4 payload (0) or IPv6 payload (1)
  - Bits 1-7: Reserved
- **Reserved** (1 byte): Reserved for future use, must be 0x00
- **Tunnel ID** (4 bytes): Unique identifier for the tunnel endpoint
- **Sequence Number** (4 bytes): Monotonically increasing packet sequence number
- **Timestamp** (4 bytes): Unix timestamp in milliseconds (lower 32 bits)
- **HMAC-SHA256** (16 bytes): First 16 bytes of HMAC-SHA256(PSK, header[0:12] + payload)
- **Payload** (variable): Encapsulated IP packet (IPv4 or IPv6)

## Message Types

### DATA (0x01)
Carries an encapsulated IP packet. The payload contains the complete IP packet including IP header.

### KEEPALIVE (0x02)
Sent periodically to maintain tunnel state. Payload is empty or contains optional statistics.

### CONTROL (0x03)
Control messages for tunnel management. Payload format depends on control subtype.

## Security

### Authentication
All packets include HMAC-SHA256 authentication using a pre-shared key (PSK). The HMAC is computed over:
- Header bytes 0-11 (version through timestamp)
- Complete payload

Recipients MUST verify the HMAC before processing packets.

### Encryption
Current version uses plaintext payload with authentication. Future versions may add encryption.

## MTU Considerations
- Recommended TUN interface MTU: 1400 bytes
- Maximum payload size: 1400 bytes (to fit in typical 1500 byte Ethernet frame with overhead)
- Outer UDP/IP overhead: ~28 bytes (IPv4) or ~48 bytes (IPv6)
- Tunnel header: 32 bytes (16 byte header + 16 byte HMAC)
- Total overhead: 60-80 bytes

## Keepalive Behavior
- Endpoints SHOULD send KEEPALIVE packets every 10 seconds when no DATA packets are sent
- Tunnel is considered dead if no packets received for 30 seconds
- Routing servers SHOULD respond to KEEPALIVE with KEEPALIVE

## Sequence Numbers
- Sequence numbers start at 0 and increment for each packet
- Used for detecting packet loss and reordering
- Wrap around at 2^32

## Timestamp Usage
- Used for RTT measurement
- Used for detecting stale packets
- Packets with timestamps older than 60 seconds SHOULD be discarded
