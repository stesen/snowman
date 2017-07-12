set(SOURCES
    Arm64Architecture.cpp
    Arm64Architecture.h
    Arm64Disassembler.cpp
    Arm64Disassembler.h
    Arm64Instruction.h
    Arm64InstructionAnalyzer.cpp
    Arm64InstructionAnalyzer.h
    Arm64Registers.cpp
    Arm64Registers.h
    CallingConventions.cpp
    CallingConventions.h
)

add_library(nc-arch-arm64 ${SOURCES})
target_link_libraries(nc-arch-arm64 nc-core nc-common capstone-static ${Boost_LIBRARIES} ${QT_LIBRARIES})

# vim:set et sts=4 sw=4 nospell:
