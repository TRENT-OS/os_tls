#
# OS TLS Library
#
# We have three library targets:
# 1. OS_TLS:
#    Provides only functionality of the TLS library behind calls to the API.
# 2. OS_TLS_WITH_RPC_CLIENT:
#    Provides library functionality to execute TLS locally, but also allows
#    to operate TLS API in RPC client mode, where calls to the API are
#    transparently mapped to an RPC interface and executed in a separate component
#    (e.g., the TlsRpcServer)
# 3. OS_TLS_WITH_RPC_SEVER:
#    Provides library functionality to execute TLS locally, but also allows
#    to instantiate the TLS API as RPC server easily, which can then be used
#    to serve RPC requests from a TLS API RPC client.
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)

# We need to build 3rdparty/mbedtls for this and would like to avoid
# all users of OS_CRYPTO to include this as well, so we do it here
os_use_libs(
    3RDPARTY_MBEDTLS_FOR_TLS
)

# These are the sources we ALWAYS compile, for all targets
set(SOURCES
    "src/OS_Tls.c"
    "src/lib/TlsLib.c"
)

set(COMPILE_DEFINITIONS)

set(COMPILE_OTIONS
    -Wall
)



#------------------------------------------------------------------------------
project(os_tls C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES}
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_OTIONS}
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_tls
        os_core_api
        os_libs
)


#------------------------------------------------------------------------------
project(os_tls_with_rpc_client C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES}
        "src/rpc/TlsLibClient.c"
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_OPTIONS}
        -DOS_TLS_WITH_RPC_CLIENT
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_tls
        os_core_api
        os_libs
)


#------------------------------------------------------------------------------
project(os_tls_with_rpc_server C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${SOURCES}
        "src/rpc/TlsLibServer.c"
)

target_compile_definitions(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_DEFINITIONS}
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
        ${COMPILE_OPTIONS}
        -DOS_TLS_WITH_RPC_SERVER
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "inc"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_tls
        os_core_api
        os_libs
)


#------------------------------------------------------------------------------
# if invoked from the OS sandbox, provide a documentation build target
if (COMMAND os_create_doxygen_target)

    os_create_doxygen_target( os_tls_doc
        # API header is documented as part of os_core_api, so we do nothing
        "echo"
        # API header is documented as part of os_core_api, so we do nothing
        "echo"
    )

endif()
