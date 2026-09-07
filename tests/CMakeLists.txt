add_executable(test_config
    test_config.c
)

target_include_directories(test_config PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_config PRIVATE
    pxc_common
)

add_test(NAME ConfigParserTest COMMAND test_config)

add_executable(test_protocol
    test_protocol.c
)

target_include_directories(test_protocol PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_protocol PRIVATE
    pxc_core
    pxc_common
    ws2_32
)

add_test(NAME ProtocolCoreTest COMMAND test_protocol)

add_executable(test_tunnel
    test_tunnel.c
)

target_include_directories(test_tunnel PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_tunnel PRIVATE
    pxc_core
    pxc_common
    ws2_32
)

add_test(NAME TunnelEngineTest COMMAND test_tunnel)

add_executable(test_fake_ip
    test_fake_ip.c
)

target_include_directories(test_fake_ip PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_fake_ip PRIVATE
    pxc_dns
    pxc_common
    ws2_32
)

add_test(NAME FakeIpTest COMMAND test_fake_ip)

add_executable(test_dns_hooks
    test_dns_hooks.c
    ${CMAKE_SOURCE_DIR}/src/hook/dns_hooks.c
)

target_include_directories(test_dns_hooks PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_dns_hooks PRIVATE
    pxc_dns
    pxc_common
    detours_static
    ws2_32
)

add_test(NAME DnsHooksTest COMMAND test_dns_hooks)

add_executable(test_winsock_hooks
    test_winsock_hooks.c
    ${CMAKE_SOURCE_DIR}/src/hook/dns_hooks.c
    ${CMAKE_SOURCE_DIR}/src/hook/winsock_hooks.c
)

target_include_directories(test_winsock_hooks PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_winsock_hooks PRIVATE
    pxc_core
    pxc_dns
    pxc_common
    detours_static
    ws2_32
)

add_test(NAME WinsockHooksTest COMMAND test_winsock_hooks)

add_executable(test_process_hooks
    test_process_hooks.c
    ${CMAKE_SOURCE_DIR}/src/hook/process_hooks.c
)

target_include_directories(test_process_hooks PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_process_hooks PRIVATE
    pxc_common
    detours_static
    ws2_32
)

add_test(NAME ProcessHooksTest COMMAND test_process_hooks)

