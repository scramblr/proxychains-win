add_library(proxychains_hook SHARED
    dllmain.c
    dns_hooks.c
    winsock_hooks.c
    process_hooks.c
)

set_target_properties(proxychains_hook PROPERTIES
    OUTPUT_NAME "${PXC_DLL_NAME}"
)

target_include_directories(proxychains_hook PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(proxychains_hook PRIVATE
    pxc_common
    pxc_core
    pxc_dns
    detours_static
    ws2_32
)
