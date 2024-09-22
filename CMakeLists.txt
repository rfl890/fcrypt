cmake_minimum_required(VERSION 3.18)
project(fcrypt VERSION 1.2 LANGUAGES C)
include(FetchContent)
include(FindGit)
include(CTest)
include(CheckLinkerFlag)

# Check linker flag to change stack size
check_linker_flag(C "LINKER:/STACK:4194304" STACK_SIZE_FLAG_VC_STYLE)
check_linker_flag(C "LINKER:-z,stack-size=4194304" STACK_SIZE_FLAG_GNU_STYLE)
check_linker_flag(C "LINKER:--stack,4194304" STACK_SIZE_FLAG_MINGW_STYLE)
check_linker_flag(C "LINKER:-stack_size,4194304" STACK_SIZE_FLAG_MACOSX_STYLE)


if (NOT (STACK_SIZE_FLAG_VC_STYLE OR STACK_SIZE_FLAG_GNU_STYLE OR STACK_SIZE_FLAG_MINGW_STYLE OR STACK_SIZE_FLAG_MACOSX_STYLE))
    message(FATAL_ERROR "Failed to determine linker flag to set the stack size.")
endif()

# Get commit hash
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_STRIP_TRAILING_WHITESPACE
        OUTPUT_VARIABLE GIT_COMMIT_HASH
    	ERROR_VARIABLE GIT_FAILED
    )
else()
    set(GIT_COMMIT_HASH "n/a")
endif()

# LibreSSL
set(LIBRESSL_TESTS off)
set(LIBRESSL_APPS off)
FetchContent_Declare(
    libressl
    URL
        "https://github.com/libressl/portable/releases/download/v3.9.2/libressl-3.9.2.tar.gz"
        PATCH_COMMAND
        patch -p1 -i ${CMAKE_SOURCE_DIR}/patches/libressl-fix-mingw-asm.patch
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_MakeAvailable(libressl)

# Blake3
FetchContent_Declare(
    blake3
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/dependencies/blake3/"
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_MakeAvailable(blake3)

# Argon2
set(argon2_src
    argon2.c
    core.c
    encoding.c
    thread.c
    blake2/blake2b.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    list(APPEND argon2_src opt.c)
else()
    list(APPEND argon2_src ref.c)
endif()

list(TRANSFORM argon2_src PREPEND "${CMAKE_SOURCE_DIR}/dependencies/argon2/")
add_library(argon2 ${argon2_src})
target_include_directories(
    argon2
    PUBLIC "${CMAKE_SOURCE_DIR}/dependencies/argon2/include"
)

# libprogress
add_library(progress "${CMAKE_SOURCE_DIR}/dependencies/libprogress/progress.c")
target_include_directories(
    progress
    PUBLIC "${CMAKE_SOURCE_DIR}/dependencies/libprogress"
)

# getopt
if(MSVC)
    add_library(getopt "${CMAKE_SOURCE_DIR}/deps/getopt/getopt.c")
    target_include_directories(getopt PUBLIC "${CMAKE_SOURCE_DIR}/deps/getopt")
endif()

# fcrypt
configure_file(
    "${CMAKE_SOURCE_DIR}/src/cmake-generated.h.in"
    "${CMAKE_BINARY_DIR}/generated/cmake-generated.h"
)
set(fcrypt_src
    main.c
    crypto-encrypt.c
    crypto-decrypt.c
    encrypt.c
    decrypt.c
    key-derivation.c
    parse-args.c
)
list(TRANSFORM fcrypt_src PREPEND "${CMAKE_SOURCE_DIR}/src/")
add_executable(fcrypt ${fcrypt_src})

target_compile_definitions(fcrypt PRIVATE CMAKE_COMPILING)

target_include_directories(fcrypt PRIVATE "${CMAKE_BINARY_DIR}/generated")

target_link_libraries(fcrypt crypto)
target_link_libraries(fcrypt blake3)
target_link_libraries(fcrypt argon2)
target_link_libraries(fcrypt progress)
if(MSVC)
    target_link_libraries(fcrypt getopt)
endif()

# set the stack size
if(STACK_SIZE_FLAG_VC_STYLE)
target_link_options(fcrypt PRIVATE "LINKER:/STACK:4194304")
elseif(STACK_SIZE_FLAG_GNU_STYLE)
target_link_options(fcrypt PRIVATE "LINKER:-z,stack-size=4194304")
elseif(STACK_SIZE_FLAG_MINGW_STYLE)
target_link_options(fcrypt PRIVATE "LINKER:--stack,4194304")
else()
target_link_options(fcrypt PRIVATE "LINKER:-stack_size,4194304")
endif()

# tests & install rules
add_executable(lua "${CMAKE_SOURCE_DIR}/dependencies/minilua/lua.c")
if(NOT WIN32)
    target_link_libraries(lua PRIVATE m)
endif()

configure_file("${CMAKE_SOURCE_DIR}/tests/util.lua" "${CMAKE_BINARY_DIR}/util.lua" COPYONLY)

add_test(NAME ZeroLength COMMAND lua "${CMAKE_SOURCE_DIR}/tests/zero.lua" "${CMAKE_BINARY_DIR}/fcrypt${CMAKE_EXECUTABLE_SUFFIX}")
add_test(NAME BlockSizeAlign COMMAND lua "${CMAKE_SOURCE_DIR}/tests/block_size_align.lua" "${CMAKE_BINARY_DIR}/fcrypt${CMAKE_EXECUTABLE_SUFFIX}")

install(TARGETS fcrypt DESTINATION bin)