cmake_minimum_required(VERSION 3.20)
project(proxychains_win VERSION 0.5.2 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PXC_ARCH "64")
    set(PXC_DLL_NAME "proxychains64")
else()
    set(PXC_ARCH "32")
    set(PXC_DLL_NAME "proxychains32")
endif()

message(STATUS "Configuring proxychains-win [${PXC_ARCH}-bit target]")

if(MSVC)
    add_compile_options(
        /W4
        /WX
        /permissive-
        /GS
        /guard:cf
        /utf-8
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/Oi>
    )
    add_link_options(
        /DYNAMICBASE
        /NXCOMPAT
        /guard:cf
    )
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        add_link_options(/HIGHENTROPYVA)
    endif()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include(cmake/Dependencies.cmake)

enable_testing()

add_subdirectory(src/common)
add_subdirectory(src/core)
add_subdirectory(src/dns)
add_subdirectory(src/hook)
add_subdirectory(src/cli)
add_subdirectory(tests)
