cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2 CACHE STRING "Pico SDK board")
set_property(CACHE PICO_BOARD PROPERTY STRINGS pico pico2)
if(NOT PICO_BOARD STREQUAL "pico" AND NOT PICO_BOARD STREQUAL "pico2")
    message(FATAL_ERROR
        "Unsupported PICO_BOARD=${PICO_BOARD}; choose pico or pico2 (non-W).")
endif()
# Build the picotool revision paired with the selected SDK instead of accepting
# an incompatible host installation. A caller can explicitly set this OFF.
set(PICOTOOL_FORCE_FETCH_FROM_GIT ON CACHE BOOL
    "Build the Pico SDK's matching picotool revision")
if(NOT PICO_SDK_PATH)
    if(DEFINED ENV{PICO_SDK_PATH})
        set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}")
    else()
        message(FATAL_ERROR
            "Set PICO_SDK_PATH to a Raspberry Pi Pico SDK checkout.")
    endif()
endif()
include(${PICO_SDK_PATH}/pico_sdk_init.cmake)

project(fido-fidelis C CXX ASM)
set(CMAKE_C_STANDARD 11)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(FIDO_FIDELIS_CONFIG "${CMAKE_CURRENT_LIST_DIR}/firmware.json"
    CACHE FILEPATH "Firmware profile, payload, and shaping configuration")
if(NOT IS_ABSOLUTE "${FIDO_FIDELIS_CONFIG}")
    get_filename_component(FIDO_FIDELIS_CONFIG "${FIDO_FIDELIS_CONFIG}" ABSOLUTE
        BASE_DIR "${CMAKE_CURRENT_LIST_DIR}")
endif()

file(GLOB FIDO_FIDELIS_PROFILES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_LIST_DIR}/profiles/*.json")
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(GENERATED_DESCRIPTORS "${GENERATED_DIR}/descriptors.h")

add_custom_command(
    OUTPUT "${GENERATED_DESCRIPTORS}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/tools/gen_descriptors.py"
            --config "${FIDO_FIDELIS_CONFIG}"
            --profiles "${CMAKE_CURRENT_LIST_DIR}/profiles"
            --out "${GENERATED_DESCRIPTORS}"
    DEPENDS
        "${FIDO_FIDELIS_CONFIG}"
        "${CMAKE_CURRENT_LIST_DIR}/tools/gen_descriptors.py"
        "${CMAKE_CURRENT_LIST_DIR}/tools/payload.py"
        "${CMAKE_CURRENT_LIST_DIR}/tools/profile_data.py"
        "${CMAKE_CURRENT_LIST_DIR}/tools/uvc_descriptors.py"
        ${FIDO_FIDELIS_PROFILES}
    COMMENT "Generating profile-specific USB descriptors"
    VERBATIM
)
add_custom_target(fido-fidelis-generate DEPENDS "${GENERATED_DESCRIPTORS}")
set_source_files_properties("${GENERATED_DESCRIPTORS}" PROPERTIES GENERATED TRUE)

# The firmware is pure C. Disable Pico SDK C++ runtime features and provide
# compatibility headers for toolchains without libstdc++.
set(PICO_CXX_ENABLE_EXCEPTIONS 0)
set(PICO_CXX_ENABLE_RTTI 0)
set(PICO_CXX_ENABLE_CXA_ATEXIT 0)
include_directories(BEFORE SYSTEM "${CMAKE_CURRENT_LIST_DIR}/firmware/stubs")
add_compile_definitions(PICO_CXX_DISABLE_ALLOCATION_OVERRIDES=1)

pico_sdk_init()

add_executable(fido-fidelis firmware/main.c "${GENERATED_DESCRIPTORS}")
add_dependencies(fido-fidelis fido-fidelis-generate)

target_link_libraries(fido-fidelis
    pico_stdlib
    tinyusb_device
    tinyusb_board
)

get_target_property(_libs fido-fidelis LINK_LIBRARIES)
list(REMOVE_ITEM _libs pico_cxx_options)
set_target_properties(fido-fidelis PROPERTIES
    LINK_LIBRARIES "${_libs}"
    LINKER_LANGUAGE C
)

target_include_directories(fido-fidelis PRIVATE
    "${GENERATED_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/firmware"
)

pico_enable_stdio_usb(fido-fidelis 0)
pico_enable_stdio_uart(fido-fidelis 1)
pico_add_extra_outputs(fido-fidelis)
