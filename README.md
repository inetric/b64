#B64

Base64 implementation satisfying the following requirements:

**Stateful:**
    Small state size and able to process streams of data  
**Immediate Output:**
    Output decoded data as soon as possible  
**No assumption on input length:**
    Process data even if only one byte is available  
**Ignore invalid bytes within input:**
    Can process base64 data that includes invalid bytes [*]

>[*]
Aside from this requirement, the implementation follows [RFC 4648][].
This requirement makes the implementation unsuitable for certain applications
without preprocessing the input. See [RFC 4648 - Security Considerations][1].

[RFC 4648]: http://tools.ietf.org/html/rfc4648 "RFC 4648"
[1]: http://tools.ietf.org/html/rfc4648#section-12
     "RFC 4648 Security Considerations"
