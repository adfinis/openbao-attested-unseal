---
title: "Code Quality"
description: "Strict typed Go conventions and local quality gates."
weight: 10
---

# Code Quality

This project handles unseal and wrapping-key lifecycle paths. The codebase
therefore starts with strict defaults:

- no broad dynamic Go types in production code;
- no Viper or environment reads outside configuration boundaries;
- no runtime panics;
- no disabled TLS verification;
- no sensitive log fields;
- typed DTOs at protocol boundaries;
- redacted command output and logs.

Run the local quality gate with:

```sh
make ci-core
```
