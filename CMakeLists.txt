cmake_minimum_required(VERSION 3.14)
project(fcrypt
        VERSION 0.1
        LANGUAGES C
)
include(ExternalProject)
include(FindGit)

option(USE_SANITIZERS "Enables the use of ASan and UBSan." OFF)
option(BUILD_X86_64_V3 "Enables x86-64-v3 optimizations for Argon2." OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

if (USE_SANITIZERS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,undefined")
endif()

if (MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:4194304")
elseif (MINGW AND ("${CMAKE_C_COMPILER_ID}" MATCHES "Clang"))
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,4194304")
else()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,stack-size=4194304")
endif()


execute_process(COMMAND
    ${GIT_EXECUTABLE} rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_STRIP_TRAILING_WHITESPACE
    OUTPUT_VARIABLE GIT_COMMIT_HASH
)

set(argon2_sources
    argon2.c
    core.c
    encoding.c
    thread.c
    blake2/blake2b.c
)

if(BUILD_X86_64_V3)
if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /ARCH:AVX2")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=x86-64-v3")
endif()
list(APPEND argon2_sources opt.c)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    # SSE2 version
    list(APPEND argon2_sources opt.c)
else()
    list(APPEND argon2_sources ref.c)
endif()

list(TRANSFORM argon2_sources PREPEND "${CMAKE_SOURCE_DIR}/deps/argon2/")

add_library(argon2 ${argon2_sources})
target_include_directories(argon2 PRIVATE "${CMAKE_SOURCE_DIR}/deps/argon2/include")


ExternalProject_Add(libressl
    PREFIX "${CMAKE_BINARY_DIR}/deps"
    URL "https://github.com/libressl/portable/releases/download/v3.9.2/libressl-3.9.2.tar.gz"
    PATCH_COMMAND patch -p1 CMakeLists.txt ${CMAKE_SOURCE_DIR}/patches/libressl-fix-mingw-asm.patch
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} crypto
    INSTALL_COMMAND ""
    CMAKE_ARGS
        -DLIBRESSL_SKIP_INSTALL=on
        -DLIBRESSL_TESTS=off
        -DLIBRESSL_APPS=off
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=${CMAKE_INTERPROCEDURAL_OPTIMIZATION}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
    DOWNLOAD_EXTRACT_TIMESTAMP true
    UPDATE_DISCONNECTED true
)

configure_file("${CMAKE_SOURCE_DIR}/src/cmake-generated.h.in" "${CMAKE_BINARY_DIR}/generated/cmake-generated.h")

set(fcrypt_sources
    main.c
    encrypt.c
    decrypt.c
    key-derivation.c
    parse-args.c
)
list(TRANSFORM fcrypt_sources PREPEND "${CMAKE_SOURCE_DIR}/src/")

add_executable(fcrypt ${fcrypt_sources})
add_dependencies(fcrypt libressl)

target_compile_definitions(fcrypt PRIVATE CMAKE_COMPILING=1)

target_include_directories(fcrypt PRIVATE "${CMAKE_SOURCE_DIR}/deps/argon2/include")
target_include_directories(fcrypt PRIVATE "${CMAKE_BINARY_DIR}/deps/src/libressl-build/include")
target_include_directories(fcrypt PRIVATE "${CMAKE_BINARY_DIR}/generated")


target_link_directories(fcrypt PRIVATE "${CMAKE_BINARY_DIR}/deps/src/libressl-build/crypto")

target_link_libraries(fcrypt PRIVATE argon2)
target_link_libraries(fcrypt PRIVATE crypto)

if(WIN32)
    target_link_libraries(fcrypt PRIVATE ws2_32)
    target_link_libraries(fcrypt PRIVATE ntdll)
    target_link_libraries(fcrypt PRIVATE bcrypt)
endif()