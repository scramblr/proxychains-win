add_library(pxc_common STATIC
    config.c
)

target_include_directories(pxc_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(pxc_common PUBLIC
    ws2_32
)
