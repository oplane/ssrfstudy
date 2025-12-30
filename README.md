# Code That Looks Secure vs. Code That Actually Is: An SSRF Case Study

Would your code catch `http://2130706433/` as localhost?

This SSRF mitigation didn't. And it passed code review.

Here's a subset of a real SSRF mitigation that Cursor + Claude implemented:
```python
LOCALHOST_PATTERN = re.compile(
    r'^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])', 
    re.IGNORECASE
)
INTERNAL_IP_PATTERN = re.compile(
    r'^https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)', 
    re.IGNORECASE
)

def validate_url(url):
    if LOCALHOST_PATTERN.match(url):
        raise ValueError("Localhost not allowed")
    if INTERNAL_IP_PATTERN.match(url):
        raise ValueError("Internal IP not allowed")
```

Looks reasonable. But I tested these with Python's `requests.get()`. Every single one bypasses the regex AND successfully connects:
```
http://2130706433/                # Decimal IP for 127.0.0.1
http://0x7f000001/                # Hex
http://[::ffff:127.0.0.1]/        # IPv4-mapped IPv6
http://google.com@127.0.0.1/      # Hostname is actually 127.0.0.1
" http://127.0.0.1/"              # Leading space
"\thttp://127.0.0.1/"             # Leading tab
```

## What's at stake?

These aren't theoretical risks. SSRF bypasses can let attackers:

- **Steal cloud credentials** - access `http://169.254.169.254/` to retrieve AWS/GCP/Azure IAM tokens, then pivot to your entire infrastructure
- **Reach internal services** - hit admin panels, databases, and APIs that assume "internal = trusted"
- **Exfiltrate data** - access internal documentation, secrets vaults, or customer data

This is how major breaches happen. In 2019, Capital One lost 100 million customer records when an attacker used SSRF to access AWS metadata credentials. Shopify, GitLab, and others have paid significant bug bounties for similar SSRF bypasses to internal services.

**The business impact:** regulatory fines, breach notification costs, incident response, legal exposure, and reputation damage. Capital One paid over $300 million in settlements and remediation. And it started with one bypassable validation function.

## Why does this happen?

Regex pattern-matches the *string*. But `requests.get()` interprets the *URL* - and those aren't the same thing. Leading whitespace? Stripped. Decimal IP? Converted. The attacker isn't trying to match your regex; they're trying to reach your internal network.

**The core issue: regex denylists fail by allowing.** Every bypass you don't enumerate gets through.

## Won't SAST catch this?

No. SAST tools detect the *absence* of validation, not *inadequate* validation. They see a regex check before a network request and move on - "SSRF mitigation present, no finding."

SAST doesn't understand bypass semantics. It doesn't know that `http://2130706433/` resolves to localhost, or that `requests.get()` strips leading whitespace. It pattern-matches code, not attacker behavior.

## The fix: parse first, validate the actual URL

Instead of pattern-matching strings, extract the hostname and validate its properties:
```python
from urllib.parse import urlparse
import ipaddress

def validate_url(url):
    parsed = urlparse(url)
    
    if not parsed.hostname:
        raise ValueError("Invalid URL")
    
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local:
            raise ValueError("Restricted IP")
    except ValueError:
        pass  # It's a hostname, not an IP
```

This is still a denylist - but a far more robust one. By parsing the URL first and validating the *actual* IP address, `ipaddress.is_loopback` handles all representations of `127.0.0.1` - decimal, hex, IPv4-mapped IPv6 - because it checks the parsed value, not string patterns.

| Approach | Behavior | Failure Mode |
|----------|----------|--------------|
| Regex denylist | Blocks string patterns you've enumerated | Fails open - encoding tricks bypass it |
| Parsed denylist | Blocks IP properties after parsing | More robust - handles encoding variations |
| Allowlist | Only permits explicitly approved destinations | Fails closed - safest when feasible |

For maximum security, consider an allowlist approach if your use case permits - only allow URLs to specific, known-good destinations rather than trying to block all bad ones.

## But fixing this one function isn't enough.

This isn't about blaming the AI - it generated a pattern it's seen thousands of times. A human would easily have made the exact same mistake.

The real question is: how do we systematically improve and drive scalable, robust security practices across an entire codebase?

## The challenge: your codebase isn't static.

Use cases change overnight. New integrations get added. Business logic evolves. That URL validator that was "good enough" last quarter might now be handling user-supplied webhooks or third-party callbacks with completely different trust assumptions. Security mitigations must evolve in lockstep - or they silently become vulnerabilities.

You shouldn't need to wait for a late and expensive pentest to catch issues like this. These bypasses aren't novel - they're well-documented techniques that should be caught continuously, as code is written.

## Fixing at scale: the Oplane approach

We help teams close the gap between code that looks secure and code that actually is:

1. **Understand business logic and intended use cases** - security that doesn't account for what the code needs to do ends up too permissive or breaks in production. As your use cases evolve, so should your threat model.

2. **Autonomous threat modeling to pinpoint security hot spots** - ongoing analysis that identifies where SSRF, injection, and other risks live in your codebase as it evolves. Not a one-time diagram that's outdated by the next sprint.

3. **Security recommendations your coding agent can follow** - give AI assistants the context to generate secure code in the first place, built on proven mitigations rather than pattern-matching from training data.

4. **Verify that the coding agent followed secure practices** - close the loop by checking that generated code actually implements mitigations correctly, catching gaps like the regex denylist above before they ship.

AI is accelerating how fast we write code. Oplane helps make sure security keeps pace - continuously, not just at checkpoints.

**Want to see how Oplane works for your codebase?** [Get in touch](mailto:hello@oplane.io) or visit [oplane.io](https://www.oplane.io)
