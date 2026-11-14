# Product

<!-- impeccable:product-schema 1 -->

## Platform

android

## Stack

Flutter Android TV client with a controlled REA backend. The existing REA Node.js/MCP engine remains the analysis implementation boundary; Flutter is the TV-first operator client.

## Users

A reverse-engineering operator using an Android TV or large-screen Android device with a D-Pad remote. The operator selects local or backend-admitted artifacts, starts bounded analyses, and reviews evidence without needing a desktop terminal.

## Product Purpose

Turn REA investigations into a legible, remote-friendly large-screen workflow: select a target, choose an analysis capability, monitor bounded progress, and inspect evidence and limitations.

## Positioning

Evidence-first reverse engineering on a TV-sized screen. Every result keeps the operation, artifact identity, confidence, authority, limitations, and source location visible instead of presenting an unsupported black-box answer.

## Operating Context

The Android TV client connects to a controlled backend over an operator-configured URL. The backend owns artifact access, REA tool execution, evidence persistence, and authentication. The client must remain useful when no target or backend is configured by showing explicit empty and setup states.

## Capabilities and Constraints

- TV landscape layout and D-Pad navigation are primary.
- Backend operations are bounded and asynchronous.
- Evidence is read-only in the first client slice.
- No APK, binary, or arbitrary shell execution occurs on the Android TV client.
- The backend contract must preserve target digest, operation, normalized result, confidence, authority, limitations, locations, and linked evidence IDs.
- The full REA catalog is represented by capability families; individual tools can be added without redesigning navigation.
- Authentication, TLS policy, and artifact admission remain backend responsibilities.

## Brand Commitments

Product name: REA TV. Preserve the REA evidence-led vocabulary: target, operation, evidence, confidence, authority, limitation, and coverage.

## Evidence on Hand

- Source repository: `/root/work/rea`
- REA current checkout: `a6f98e733eb0efd9b62b740fb9d847c098925e99`
- REA exposes Android APK, Flutter AOT, native binary, web, managed-code, firmware, capture, and evidence workflows through CLI/MCP contracts.
- No Flutter SDK is installed on the current host; source-level and bounded static checks are available, while APK compilation remains unverified until a Flutter toolchain is supplied.

## Product Principles

- Evidence before interpretation.
- Remote-friendly focus is a product requirement, not a finishing detail.
- Show limitations beside conclusions.
- Keep destructive or execution-capable actions outside the TV client.
- Make backend and artifact state explicit at every step.

## Accessibility & Inclusion

High-contrast focus treatment, large readable type, no hover-only affordances, visible loading/error/empty states, and activation through Select/Enter/game-button variants.
