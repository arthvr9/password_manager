cmake_minimum_required(VERSION 3.21)
project(pass-manager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "$ENV{HOME}/.local" CACHE PATH "" FORCE)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets DBus)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_compile_options(-Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2)
add_link_options(-pie -Wl,-z,relro,-z,now)

add_executable(pass-manager main.cpp vault.cpp sandbox.cpp)
target_link_libraries(pass-manager Qt6::Widgets Qt6::DBus PkgConfig::SODIUM)

add_executable(vault_test vault_test.cpp vault.cpp)
target_compile_options(vault_test PRIVATE -UNDEBUG)
target_link_libraries(vault_test Qt6::Core PkgConfig::SODIUM)

add_executable(sandbox_test sandbox_test.cpp sandbox.cpp)
target_compile_options(sandbox_test PRIVATE -UNDEBUG)
target_link_libraries(sandbox_test Qt6::Core)

configure_file(pass-manager.desktop.in pass-manager.desktop @ONLY)
install(TARGETS pass-manager)
install(FILES ${CMAKE_BINARY_DIR}/pass-manager.desktop DESTINATION share/applications)
