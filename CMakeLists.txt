#
# OS TLS
#
# Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#------------------------------------------------------------------------------
project(os_tls C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_Tls.c"
        "src/lib/TlsLib.c"
        "src/rpc/TlsLibClient.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_tls_client
        os_core_api
        lib_compiler
        lib_debug
        lib_macros
)

#------------------------------------------------------------------------------
project(os_tls_server C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_Tls.c"
        "src/lib/TlsLib.c"
        "src/rpc/TlsLibClient.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_tls_server
        os_core_api
        lib_compiler
        lib_debug
        lib_macros
)
