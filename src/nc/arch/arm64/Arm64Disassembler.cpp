/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#include "Arm64Disassembler.h"

#include <nc/common/make_unique.h>

#include "Arm64Architecture.h"
#include "Arm64Instruction.h"

namespace nc {
namespace arch {
namespace arm64 {

Arm64Disassembler::Arm64Disassembler(const Arm64Architecture *architecture):
    core::arch::Disassembler(architecture)
{
    mode_ = CS_MODE_ARM;
    capstone_ = std::make_unique<core::arch::Capstone>(CS_ARCH_ARM64, mode_);
}

Arm64Disassembler::~Arm64Disassembler() {}

std::shared_ptr<core::arch::Instruction> Arm64Disassembler::disassembleSingleInstruction(ByteAddr pc, const void *buffer, ByteSize size) {
    if (auto instr = capstone_->disassemble(pc, buffer, size, 1)) {
        /* Instructions must be aligned to their size. */
        if ((instr->address & (instr->size - 1)) == 0) {
            return std::make_shared<Arm64Instruction>(mode_, instr->address, instr->size, buffer);
        }
    }
    return nullptr;
}

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
