# SEOS Crypto Library

project(seos_tls C)

add_library(
    ${PROJECT_NAME} STATIC
    "src/SeosTlsApi.c"
)
if (ENABLE_LINT)
        set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
        set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

# when building for the x64 architecture, some warnings are
# reported (i.e. printf formatting) that the code is full of,
# and that are otherwise not reported, so as a quick fix we
# remove the -Werror in this build situation
if(NO_KERNEL_BUILD)
    # when building for the x64 architecture, some warnings are
    # reported (i.e. printf formatting) that the code is full of,
    # and that are otherwise not reported, so as a quick fix we
    # remove the -Werror in this build situation
    target_compile_options(${PROJECT_NAME}
        PUBLIC
            -Wall
    )

    # since PAGE_SIZE is normally defined as part of musllibc
    # (which is missing here) we have to define it
    target_compile_definitions(${PROJECT_NAME} PRIVATE PAGE_SIZE=${PAGE_SIZE_VALUE})
else()
    target_compile_options(${PROJECT_NAME}
        PUBLIC
            -Wall
            -Werror
    )
endif(NO_KERNEL_BUILD)

if (DEBUG_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "DEBUG_CONFIG_H_FILE=${DEBUG_CONFIG_H_FILE}"
    )
endif()

if (MEMORY_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "MEMORY_CONFIG_H_FILE=${MEMORY_CONFIG_H_FILE}"
    )
endif()

if (SEOS_TLS_IMPL_MBEDTLS)
    list(APPEND PRIVATE_TARGET_COMPILE_DEFINITIONS
        MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/MbedTLS_Config.h"
    )
    target_include_directories(${PROJECT_NAME}
        # TODO: Should be made PRIVATE in the future, currently we need the
        # includes from mbedTLS for their data structures
        PUBLIC
        "3rdParty/mbedtls/include"
    )
    target_sources(${PROJECT_NAME}
        PRIVATE
        "3rdParty/mbedtls/library/asn1parse.c"
        "3rdParty/mbedtls/library/certs.c"
        "3rdParty/mbedtls/library/debug.c"
#        "3rdParty/mbedtls/library/error.c"
#        "3rdParty/mbedtls/library/net_sockets.c"
        "3rdParty/mbedtls/library/pk.c"
        "3rdParty/mbedtls/library/pk_wrap.c"
        "3rdParty/mbedtls/library/pkparse.c"
        "3rdParty/mbedtls/library/oid.c"
        "3rdParty/mbedtls/library/pkcs11.c"
#        "3rdParty/mbedtls/library/ssl_cache.c"
        "3rdParty/mbedtls/library/ssl_ciphersuites.c"
        "3rdParty/mbedtls/library/ssl_cli.c"
#        "3rdParty/mbedtls/library/ssl_cookie.c"
        "3rdParty/mbedtls/library/ssl_srv.c"
#        "3rdParty/mbedtls/library/ssl_ticket.c"
        "3rdParty/mbedtls/library/ssl_tls.c"
#        "3rdParty/mbedtls/library/version.c"
#        "3rdParty/mbedtls/library/version_features.c"
        "3rdParty/mbedtls/library/x509.c"
        "3rdParty/mbedtls/library/x509_create.c"
#        "3rdParty/mbedtls/library/x509_crl.c"
        "3rdParty/mbedtls/library/x509_crt.c"
#        "3rdParty/mbedtls/library/x509_csr.c"
#        "3rdParty/mbedtls/library/x509write_crt.c"
#        "3rdParty/mbedtls/library/x509write_csr.c"
#        "3rdParty/mbedtls/library/aes.c"
#        "3rdParty/mbedtls/library/gcm.c"
#        "3rdParty/mbedtls/library/cipher.c"
        "3rdParty/mbedtls/library/platform.c"
        "3rdParty/mbedtls/library/entropy.c"
        "3rdParty/mbedtls/library/entropy_poll.c"
#        "3rdParty/mbedtls/library/md.c"
#        "3rdParty/mbedtls/library/sha256.c"
#        "3rdParty/mbedtls/library/rsa.c"
#        "3rdParty/mbedtls/library/ecp.c"
    )
endif()

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_crypto
    seos_libs
)

# if invoked from the SOES sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    get_target_property(
        SEOS_CORE_API_INCLUDES
        seos_core_api
        INTERFACE_INCLUDE_DIRECTORIES)

    find_file(
        SEOS_TLS_API_HEADER
        SeosTlsApi.h
        PATHS ${SEOS_CORE_API_INCLUDES}
        CMAKE_FIND_ROOT_PATH_BOTH)

    seos_create_doxygen_target( seos_tls_doc
        # pre-step: link the API file SeosCryptoApi.h from seos_core_api in
        #           order to produce a complete doxygen documentation
        "ln -sf ${SEOS_TLS_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include"
        # post-step: remove the link to SeosTlsApi.h
        "rm ${CMAKE_CURRENT_SOURCE_DIR}/include/SeosTlsApi.h"
        )

endif()
