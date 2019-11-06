file(GLOB HEADERS "include/elastos/elastos_plugin/*.hpp")
add_library(elastos_plugin
        elastos_plugin.cpp
        ${HEADERS})

target_link_libraries(elastos_plugin spvsdk chain_plugin producer_plugin history_plugin http_plugin appbase fc)
add_dependencies(elastos_plugin libspvsdk)
target_link_directories(elastos_plugin PUBLIC
        "${CMAKE_BINARY_DIR}/intermediates/lib"
        "${CMAKE_CURRENT_BINARY_DIR}/../../libraries/elastos/SDK")
target_include_directories(elastos_plugin PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/chain/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/appbase/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/elastos/SDK"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/elastos/Core"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/elastos/Interface"
        "${CMAKE_CURRENT_BINARY_DIR}/../../libraries/elastos"
        "${CMAKE_CURRENT_BINARY_DIR}/../../intermediates/include")
