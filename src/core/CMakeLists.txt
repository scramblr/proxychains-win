add_library(pxc_core STATIC
    protocol.c
    tunnel.c
)

target_include_directories(pxc_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(pxc_core PUBLIC
    pxc_common
    ws2_32
)
