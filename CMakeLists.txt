#
# SEOS TLS Library
#
# We have three library targets:
# 1. SEOS_TLS:
#    Provides only functionality of the TLS library behind calls to the API.
# 2. SEOS_TLS_WITH_RPC_CLIENT:
#    Provides library functionality to execute TLS locally, but also allows
#    to operate TLS API in RPC client mode, where calls to the API are
#    transparently mapped to an RPC interface and executed in a separate component
#    (e.g., the TlsRpcServer)
# 3. SEOS_TLS_WITH_RPC_SEVER:
#    Provides library functionality to execute TLS locally, but also allows
#    to instantiate the TLS API as RPC server easily, which can then be used
#    to serve RPC requests from a TLS API RPC client.
#

# These are the sources we ALWAYS compile, for all targets
set(SHARED_LIB_SOURCES
    "src/OS_Tls.c"
    "src/lib/TlsLib.c"
)

# These are the 3rd party sources, holding the actual algorithms
set(MBEDTLS_SOURCES
    # This file includes the functions we have added
    "3rdParty/mbedtls/library/crypto.c"
    # Include the minimum of C files which we need here which are not already
    # compiled in as part of the crypto API
    "3rdParty/mbedtls/library/debug.c"
    "3rdParty/mbedtls/library/pk.c"
    "3rdParty/mbedtls/library/pk_wrap.c"
    "3rdParty/mbedtls/library/pkparse.c"
    "3rdParty/mbedtls/library/ssl_ciphersuites.c"
    "3rdParty/mbedtls/library/ssl_cli.c"
    "3rdParty/mbedtls/library/ssl_tls.c"
    "3rdParty/mbedtls/library/x509.c"
    "3rdParty/mbedtls/library/pem.c"
    "3rdParty/mbedtls/library/base64.c"
    "3rdParty/mbedtls/library/x509_crt.c"
)

set(PRIVATE_TARGET_COMPILE_DEFINITIONS
    MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/MbedTLS_Config.h"
)

set(PUBLIC_TARGET_COMPILE_DEFINITIONS)

set(PRIVATE_TARGET_COMPILE_OTIONS)

set(PUBLIC_TARGET_COMPILE_OTIONS
    -Wall
)

if (ENABLE_LINT)
    set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

#------------------------------------------------------------------------------

project(seos_tls C)

add_library(${PROJECT_NAME} STATIC
    ${SHARED_LIB_SOURCES}
    ${MBEDTLS_SOURCES}
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_OPTIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_OPTIONS}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "inc"
        "3rdParty/mbedtls/include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_libs
)

#------------------------------------------------------------------------------

project(seos_tls_with_rpc_client C)

add_library(${PROJECT_NAME} STATIC
    ${SHARED_LIB_SOURCES}
    "src/rpc/TlsLibClient.c"
    ${MBEDTLS_SOURCES}
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_OPTIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_OPTIONS}
        -DSEOS_TLS_WITH_RPC_CLIENT
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "inc"
        "3rdParty/mbedtls/include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_libs
)

#------------------------------------------------------------------------------

project(seos_tls_with_rpc_server C)

add_library(${PROJECT_NAME} STATIC
    ${SHARED_LIB_SOURCES}
    "src/rpc/TlsLibServer.c"
    ${MBEDTLS_SOURCES}
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_OPTIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_OPTIONS}
        -DSEOS_TLS_WITH_RPC_SERVER
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "inc"
        "3rdParty/mbedtls/include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_libs
)

#------------------------------------------------------------------------------

# if invoked from the SEOS sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    seos_create_doxygen_target( seos_tls_doc
        # API header is documented as part of seos_core_api, so we do nothing
        "echo"
        # API header is documented as part of seos_core_api, so we do nothing
        "echo"
    )

endif()
