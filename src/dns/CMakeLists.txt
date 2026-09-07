add_library(pxc_dns STATIC
    fake_ip.c
    resolver.c
)

target_include_directories(pxc_dns PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(pxc_dns PUBLIC
    pxc_common
    ws2_32
)
