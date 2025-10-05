add_executable(LiBurn-Payload
    main.cpp
)

set_target_properties(LiBurn-Payload PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}")