# Support

OpenIDX is maintained by a very small team. This page says where to ask, what
to expect, and what is not on offer, so that nobody waits on a channel that
does not exist.

## Where to ask

- **Bugs and feature requests:** [GitHub Issues](https://github.com/mhmtgngr/openidx/issues),
  using the Bug Report or Feature Request template. Include the version
  (`VERSION`, or the image tag you deployed), the deployment path (Docker
  Compose or the Helm chart), and the service logs around the failure. A
  report that can be reproduced from its text is the one that gets fixed.
- **Security vulnerabilities:** never in a public issue. Follow
  [SECURITY.md](SECURITY.md).
- **Questions about running OpenIDX:** start with the documentation index in
  [docs/README.md](docs/README.md), in particular
  [Getting started](docs/GETTING-STARTED.md) and the
  [Operator guide](docs/docs/deployment/operator-guide.md). If the documents
  did not answer the question, open an issue and say which document you read:
  a question the documentation could not answer is a documentation bug.
- **Contributing a fix yourself:** [CONTRIBUTING.md](CONTRIBUTING.md), which
  also explains the sign-off every commit needs.

## What to expect

- **Best effort, no service level.** Issues are triaged as time allows. There
  is no guaranteed response or resolution time.
- **Supported versions:** the current 1.x release line, as
  [SECURITY.md](SECURITY.md) states for security fixes. Older lines are not
  patched.
- **Supported deployment paths:** the Docker Compose quick start and the Helm
  chart under `deployments/kubernetes/helm/openidx`, as described in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Other ways of running the services
  are not tested here and questions about them may go unanswered.

## What is not on offer

- There is no paid support tier, no support contract and no on-call rotation
  today. If that changes, this page changes first.
- Nobody will debug a production incident over an issue thread in real time.
  For an active security incident affecting an OpenIDX deployment, use the
  channel in [SECURITY.md](SECURITY.md).
