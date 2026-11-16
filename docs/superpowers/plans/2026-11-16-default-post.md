# Default POST Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan. Steps use checkbox syntax for tracking.

**Goal:** When the starter is enabled, make POST encryption the default while allowing exact path exemptions.

**Architecture:** One shared servlet/MVC policy governs both Boot 2 and Boot 3. Keep the crypto envelope and SDK unchanged; Boot 3 continues generating Jakarta imports from the shared Java sources.

**Tech Stack:** Spring Boot MVC 2.x/3.x, JDK 8/11/17/21, Maven, existing JavaScript client.

**Spec:** ../specs/2026-11-16-default-post-design.md

## Review focus

Exact exemption matching, unsupported content type, non-POST and bootstrap behavior, conflicting annotations, old settings, and forwarded plaintext. Ensure no unverified protected request reaches a handler.

- [x] Add regressions for default POST protection, opt-out, other methods, and forwarded requests; observe RED before implementation.
- [x] Replace the old route policy, update the MVC guard, and run GREEN tests across both starters.
- [x] Rebuild the six published JARs for their actual Java targets, and test both resulting frameworks over HTTP with the unchanged SDK.
- [x] Verify old artifacts remain intact and publish the new packages and migration instructions.
