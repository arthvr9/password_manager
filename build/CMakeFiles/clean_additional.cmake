# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Release")
  file(REMOVE_RECURSE
  "CMakeFiles/pass-manager_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/pass-manager_autogen.dir/ParseCache.txt"
  "CMakeFiles/vault_test_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/vault_test_autogen.dir/ParseCache.txt"
  "pass-manager_autogen"
  "vault_test_autogen"
  )
endif()
