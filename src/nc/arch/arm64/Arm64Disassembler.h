/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#pragma once

#include <nc/config.h>

#include <memory>

#include <nc/core/arch/Capstone.h>
#include <nc/core/arch/Disassembler.h>

namespace nc {
namespace arch {
namespace arm64 {

class Arm64Architecture;

/**
 * Disassembler for ARM64 architecture.
 *
 */
class Arm64Disassembler: public core::arch::Disassembler {
    std::unique_ptr<core::arch::Capstone> capstone_;
    int mode_;

public:
    Arm64Disassembler(const Arm64Architecture *architecture);

    virtual ~Arm64Disassembler();

    std::shared_ptr<core::arch::Instruction> disassembleSingleInstruction(ByteAddr pc, const void *buffer, ByteSize size) override;
};

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
