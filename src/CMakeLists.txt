find_package(SEAL 4.0 REQUIRED)

find_package(pybind11 CONFIG REQUIRED)


add_library(sealpir pir.hpp pir.cpp pir_client.hpp pir_client.cpp pir_server.hpp
  pir_server.cpp)
set_target_properties(sealpir PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(sealpir SEAL::seal)

add_executable(main main.cpp)
target_link_libraries(main sealpir)

add_library(pysealpir MODULE ../python/bindings.cpp)
target_include_directories(pysealpir PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(pysealpir PRIVATE sealpir)
target_link_libraries(pysealpir PRIVATE pybind11::module)

set_target_properties(pysealpir PROPERTIES OUTPUT_NAME "_pysealpir" PREFIX "" SUFFIX ".so")
