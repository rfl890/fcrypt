cmake_minimum_required(VERSION 3.14)
project(fcrypt VERSION 1.1 LANGUAGES C)
include(ExternalProject)
include(FindGit)
include(CTest)

option(USE_SANITIZERS "Enables the use of ASan and UBSan." OFF)
option(BUILD_X86_64_V3 "Enables x86-64-v3 optimizations for Argon2." OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

if(USE_SANITIZERS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,undefined")
endif()

if(MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:4194304")
elseif(MINGW AND ("${CMAKE_C_COMPILER_ID}" MATCHES "Clang"))
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,4194304")
else()
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,stack-size=4194304"
    )
endif()

if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE GIT_COMMIT_HASH
    )
else()
    set(GIT_COMMIT_HASH "(unavailable)")
endif()

set(argon2_sources
    argon2.c
    core.c
    encoding.c
    thread.c
    blake2/blake2b.c
)

if(BUILD_X86_64_V3)
    if(MSVC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX2")
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
target_include_directories(
    argon2
    PRIVATE "${CMAKE_SOURCE_DIR}/deps/argon2/include"
)

if(MSVC)
    add_library(getopt "${CMAKE_SOURCE_DIR}/deps/getopt/getopt.c")
    target_include_directories(getopt PRIVATE "${CMAKE_SOURCE_DIR}/deps/getopt")
endif()

ExternalProject_Add(
    libressl_src
    PREFIX "${CMAKE_BINARY_DIR}/deps/libressl"
    URL
        "https://github.com/libressl/portable/releases/download/v3.9.2/libressl-3.9.2.tar.gz"
    PATCH_COMMAND
        patch -p1 CMakeLists.txt
        ${CMAKE_SOURCE_DIR}/patches/libressl-fix-mingw-asm.patch
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} crypto
    CMAKE_ARGS
        -DLIBRESSL_TESTS=off -DLIBRESSL_APPS=off
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=${CMAKE_INTERPROCEDURAL_OPTIMIZATION}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/deps/libressl-bin
    DOWNLOAD_EXTRACT_TIMESTAMP true
    UPDATE_DISCONNECTED true
)

ExternalProject_Add(
    blake3_src
    PREFIX "${CMAKE_BINARY_DIR}/deps/blake3"
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/deps/blake3"
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=${CMAKE_INTERPROCEDURAL_OPTIMIZATION}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/deps/blake3-bin
    DOWNLOAD_EXTRACT_TIMESTAMP true
    UPDATE_DISCONNECTED true
)

configure_file(
    "${CMAKE_SOURCE_DIR}/src/cmake-generated.h.in"
    "${CMAKE_BINARY_DIR}/generated/cmake-generated.h"
)

set(fcrypt_sources
    main.c
    crypto-encrypt.c
    crypto-decrypt.c
    encrypt.c
    decrypt.c
    key-derivation.c
    parse-args.c
)
list(TRANSFORM fcrypt_sources PREPEND "${CMAKE_SOURCE_DIR}/src/")

add_executable(fcrypt ${fcrypt_sources})
add_dependencies(fcrypt libressl_src)
add_dependencies(fcrypt blake3_src)

target_compile_definitions(fcrypt PRIVATE CMAKE_COMPILING=1)

target_include_directories(
    fcrypt
    PRIVATE "${CMAKE_SOURCE_DIR}/deps/argon2/include"
)
target_include_directories(
    fcrypt
    PRIVATE "${CMAKE_BINARY_DIR}/deps/libressl-bin/include"
)
target_include_directories(
    fcrypt
    PRIVATE "${CMAKE_BINARY_DIR}/deps/blake3-bin/include"
)
target_include_directories(fcrypt PRIVATE "${CMAKE_BINARY_DIR}/generated")

target_link_directories(
    fcrypt
    PRIVATE "${CMAKE_BINARY_DIR}/deps/libressl-bin/lib"
)
target_link_directories(
    fcrypt
    PRIVATE "${CMAKE_BINARY_DIR}/deps/blake3-bin/lib"
)

target_link_libraries(fcrypt PRIVATE argon2)
target_link_libraries(fcrypt PRIVATE blake3)
target_link_libraries(fcrypt PRIVATE crypto)

if(WIN32)
    target_link_libraries(fcrypt PRIVATE ws2_32)
    target_link_libraries(fcrypt PRIVATE ntdll)
    target_link_libraries(fcrypt PRIVATE bcrypt)
endif()
if(MSVC)
    target_include_directories(fcrypt PRIVATE "${CMAKE_SOURCE_DIR}/deps/getopt")
    target_link_libraries(fcrypt PRIVATE getopt)
endif()

add_executable(lua "${CMAKE_SOURCE_DIR}/deps/minilua/lua.c")
if(NOT WIN32)
    target_link_libraries(lua PRIVATE m)
endif()

configure_file("${CMAKE_SOURCE_DIR}/tests/util.lua" "${CMAKE_BINARY_DIR}/util.lua" COPYONLY)

add_test(NAME ZeroLength COMMAND lua "${CMAKE_SOURCE_DIR}/tests/zero.lua" "${CMAKE_BINARY_DIR}/fcrypt${CMAKE_EXECUTABLE_SUFFIX}")
add_test(NAME BlockSizeAlign COMMAND lua "${CMAKE_SOURCE_DIR}/tests/block_size_align.lua" "${CMAKE_BINARY_DIR}/fcrypt${CMAKE_EXECUTABLE_SUFFIX}")

install(TARGETS fcrypt DESTINATION bin)