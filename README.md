# OS TLS

## Overview

OS TLS provides a library that allows components to establish TLS connections.

## Usage

The project creates a CMake interface library called os_tls which can be
statically linked by other projects that depend on it (libraries, components
etc.).

## 3rd Party Modules

The table lists the 3rd party modules used within this module, their licenses
and the source from which they were obtained:

| Name    | SPDX Identifier | Source                               |
|---------|-----------------|--------------------------------------|
| mbedtls | Apache-2.0      | <https://github.com/ARMmbed/mbedtls> |
