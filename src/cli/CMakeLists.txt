add_executable(proxychains
    main.c
    ${CMAKE_SOURCE_DIR}/src/hook/process_hooks.c
)

target_include_directories(proxychains PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(proxychains PRIVATE
    pxc_common
    detours_static
    ws2_32
)

add_custom_command(TARGET proxychains POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:proxychains>"
        "$<TARGET_FILE_DIR:proxychains>/proxychains-win.exe"
)
