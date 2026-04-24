---
name: new-feature
description: >-
  Add a new skeleton feature to the specs. Use when the user ask about adding
  specifications for a new EIP they are working on.
compatibility: Requires make and uv
---

# Add a new feature

This skill describes how to add a new feature to the specs. A feature represents
the specifications for an individual EIP. The features directory is a staging
area for EIPs that might be included in an upgrade.

## Collect information

Ask the user for the EIP number. If they do not have an EIP number yet, let them
know that this is a prerequisite; the specification maintainers will not merge a
new feature without an EIP number. The feature name will be `eipXXXXX` where
`XXXXX` is the EIP number.

Ask the user which upgrade they would like to base their new feature on. It is
recommended that new features are based on the latest stable upgrade. Though, an
unstable upgrade may be necessary if the feature depends on another feature.

## Update makefile

## Update actions

## Update pysetup

## Update tests

## Create specs

## Create presets
