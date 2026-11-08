# Security policy

## What netscan does with the network

netscan performs TCP **connect** scans: for every host/port pair it opens
a normal TCP connection and reports the port as open when the connection
is accepted. When banner grabbing is enabled (the default), it reads
whatever the service sends first, and for common HTTP ports it sends a
harmless `HEAD / HTTP/1.0` request and reports the `Server:` header.

connect scans deliberately **complete the TCP handshake**, so they show
up in the target's logs. They never send SYN-only probes, never spoof
addresses, and never attempt to send exploits or authentication attempts.

## Responsible use (please read)

- Only scan networks you own, or that you are explicitly authorised to
  test. Scanning a network without permission may be illegal where you
  live and may violate your ISP's or employer's acceptable-use policy.
- netscan refuses public address ranges by default (`--allow-public`
  is required to override this). This is a guardrail, not a substitute
  for authorisation.
- Banner grabbing is informational. Do not use banner or scan data to
  attack discovered services.

## Reporting a vulnerability

If you find a security issue in netscan itself (for example a way to
make the tool scan unintended addresses, an injection through parsed
`arp`/`ip neigh` output, or a denial-of-service on the operator's own
machine), please report it privately:

- Open a **private** advisory on the GitHub repository
  ("Report a vulnerability" under the Security tab), or
- Email the maintainer at the address listed on the repository profile.

Please include: the version (`netscan --version`), steps to reproduce,
and the impact you are concerned about. Do not attach scans or data
from networks you do not own.

What happens next:

- We acknowledge reports within a few days and keep you updated.
- We fix the issue, bump the version, and credit you in the changelog
  unless you prefer otherwise.
- Please do not disclose the issue publicly until a fix is released.
