# Prefix exemptions implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans; test before claiming completion.

**Goal:** Admins can place deliberately plaintext POST endpoints under one prefix.

**Architecture:** Compile an exact-exemption set and canonical prefix list in the shared PostPolicy. The servlet filter and MVC guard use the same exemption check. Boot 3 still generates its sources from the shared code.

**Tech Stack:** Spring Boot MVC 2.x/3.x, Java 8/11/17/21, existing JS wire protocol.

**Spec:** ../specs/2026-11-16-prefix-exclusions-design.md

- [x] Observe fail-first regressions on valid prefix, sibling collisions, malformed rules and raw URI spellings.
- [x] Integrate the prefix matcher, preserving exact rules, annotation conflicts and protected redispatch.
- [x] Build and test all six native JDK variants; exercise real HTTP on both Boot families.
- [x] Publish sources, artifacts and allowlist documentation, retaining older jars.
