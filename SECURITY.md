# Security policy

Frasil is under active development. Neither the
specification nor the code has had an independent security review. Do not
rely on it to protect data that matters yet.

## Reporting a vulnerability

Report vulnerabilities privately, never in a public issue, pull request or
discussion.

1. Preferred: GitHub's private vulnerability reporting. Open the
   repository's **Security** tab and choose
   [**Report a vulnerability**](https://github.com/transcodeworks/frasil/security/advisories/new).
2. If you cannot use GitHub, email
   [security@transcode.works](mailto:security@transcode.works).

Please include:

- what is affected: the crate, the npm package `@frasil/client`, the peer
  service `frasil-relay`, or the specification itself, with the version or
  commit;
- the impact: what an attacker can read, forge, alter, replay or deny, and
  from which position (a member, a former member, an always-on peer, someone
  on the network, a holder of a link);
- steps or a test that reproduces it, and the features you built with;
- for a flaw in the specification, the document and section, and whether
  the reference code in `docs/spec/reference/` shows it.

## What to expect

- An acknowledgement within 3 working days.
- An assessment, and a plan for a fix or the reason there will be none,
  within 14 days.
- Updates as the fix progresses. A fix to the protocol starts in the
  specification, so it can take longer than a fix to code alone.
- A coordinated disclosure: a GitHub security advisory published with the
  fix, crediting you unless you ask not to be named. Please keep the issue
  private until then, or for 90 days from your report, whichever is first.

## Supported versions

Frasil is before 1.0. Only the latest release receives security fixes;
there are no backports to earlier releases.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Anything earlier | No |
