cmake_minimum_required(VERSION 3.26)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /EHsc")
include(FetchContent)

# Safetyhook
set(SAFETYHOOK_FETCH_ZYDIS ON)
include(FetchContent)
FetchContent_Declare(
        safetyhook
        GIT_REPOSITORY "https://github.com/IfanSnek/safetyhook.git"
        GIT_TAG "origin/main"
)
FetchContent_MakeAvailable(safetyhook)


# OpenXR
FetchContent_Declare(
        openxr
        GIT_REPOSITORY "https://github.com/KhronosGroup/OpenXR-SDK"
        GIT_TAG "origin/main"
)
FetchContent_MakeAvailable(openxr)

# BF2VR
project(BF2VR)
add_library(
        BF2VR MODULE
        "src/BF2VR/main.cpp"
        "src/BF2VR/OpenXRService.cpp"
        "src/BF2VR/Logging.cpp"
        "src/BF2VR/D3DService.cpp"
        "src/BF2VR/BF2Service.cpp"
        "src/BF2VR/ActionsService.cpp"
)
target_include_directories(
        BF2VR PRIVATE
        "${OPENXR_SOURCE_DIR}/include"
        "${safetyhook_SOURCE_DIR}/include"
)
target_link_libraries(
        BF2VR PRIVATE
        "openxr_loader"
        "safetyhook"
        "d3d11"
        "d3dcompiler"
)
set_target_properties(BF2VR PROPERTIES PREFIX "")

# Loader
project(Loader)
add_executable(Loader
        src/Loader/main.cpp
        src/Loader/Loader.rc
)
target_link_libraries(Loader PRIVATE)