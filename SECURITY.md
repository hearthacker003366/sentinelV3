# Security Policy

## Scope & Purpose
**Sentinel V3** is an AI-augmented Security Operations Center (SOC) defense framework developed for academic research and controlled lab demonstrations. Simulated attack telemetry within `backend/detection/rules/` and synthetic scenarios are explicitly bounded to isolated virtual environments (`192.168.56.0/24`, `10.10.10.0/24`).

## Supported Versions
Active security hardening and bug fixes are maintained on the current development line:

| Version | Supported | Description |
| ------- | --------- | ----------- |
| 3.1.x / `main` | :white_check_mark: | Active research & hardened PoC releases |
| 3.0.x | :x: | Legacy simulation build |

## Reporting a Vulnerability
We welcome responsible vulnerability reports. If you discover a security vulnerability in the orchestrator, MCP server, API endpoints, or containment mechanisms:

1. **Email Disclosure**: Contact the project maintainer directly at **security@project-sentinel.local** or open a **GitHub Security Advisory** under the `Security` tab.
2. **Details to Include**:
   - Description of the vulnerability and attack vector.
   - Proof of Concept (PoC) or reproducible steps.
   - Potential impact on the host system or control plane.
3. **Response Timeline**:
   - Initial acknowledgement: Within **48 hours**.
   - Assessment & mitigation patch: Target within **7 business days**.

Please allow reasonable time for a fix before public disclosure.
