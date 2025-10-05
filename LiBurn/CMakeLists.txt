add_executable(LiBurn
    main.cpp
)

set_target_properties(LiBurn PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}")