include(FetchContent)

cmake_policy(SET CMP0169 OLD)

FetchContent_Declare(
    detours
    GIT_REPOSITORY https://github.com/microsoft/Detours.git
    GIT_TAG        v4.0.1
)

FetchContent_GetProperties(detours)
if(NOT detours_POPULATED)
    FetchContent_Populate(detours)

    set(DETOURS_SOURCES
        ${detours_SOURCE_DIR}/src/detours.cpp
        ${detours_SOURCE_DIR}/src/modules.cpp
        ${detours_SOURCE_DIR}/src/disasm.cpp
        ${detours_SOURCE_DIR}/src/image.cpp
        ${detours_SOURCE_DIR}/src/creatwth.cpp
    )

    add_library(detours_static STATIC ${DETOURS_SOURCES})
    target_include_directories(detours_static PUBLIC ${detours_SOURCE_DIR}/src)

    if(MSVC)
        target_compile_options(detours_static PRIVATE /permissive /W3 /WX-)
    endif()
endif()
