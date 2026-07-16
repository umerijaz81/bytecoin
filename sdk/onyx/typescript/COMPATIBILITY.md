# Compatibility policy

This package follows semantic versioning independently from consensus activation. Version 1 implements
Onyx wallet RPC profile v1. Patch releases may fix validation without widening accepted wire objects;
minor releases may add helpers or standardized methods without changing existing contracts. Removing
or reinterpreting a method or field, changing an encoded value, or targeting a different ABI/profile
requires a new package major version.

The package performs no implicit network access and rejects unknown fields so a server cannot silently
negotiate the client onto an unreviewed protocol extension.
