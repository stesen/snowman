/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#include "Arm64Architecture.h"

#include <nc/common/make_unique.h>

#include <nc/core/MasterAnalyzer.h>

#include "Arm64Disassembler.h"
#include "Arm64Instruction.h"
#include "Arm64InstructionAnalyzer.h"
#include "Arm64Registers.h"
#include "CallingConventions.h"

namespace nc {
namespace arch {
namespace arm64 {

Arm64Architecture::Arm64Architecture(ByteOrder byteOrder):
    byteOrder_(byteOrder)
{
    setName(QLatin1String("arm64"));
    setBitness(32);
    setMaxInstructionSize(Arm64Instruction::maxSize());

    setRegisters(Arm64Registers::instance());

    static core::MasterAnalyzer masterAnalyzer;
    setMasterAnalyzer(&masterAnalyzer);

    addCallingConvention(std::make_unique<DefaultCallingConvention>());
}

Arm64Architecture::~Arm64Architecture() {}

ByteOrder Arm64Architecture::getByteOrder(core::ir::Domain domain) const {
    if (domain == core::ir::MemoryDomain::MEMORY ||
        domain == core::ir::MemoryDomain::STACK)
    {
        return byteOrder_;
    } else {
        return ByteOrder::LittleEndian;
    }
}

std::unique_ptr<core::arch::Disassembler> Arm64Architecture::createDisassembler() const {
    return std::make_unique<Arm64Disassembler>(this);
}

std::unique_ptr<core::irgen::InstructionAnalyzer> Arm64Architecture::createInstructionAnalyzer() const {
    return std::make_unique<Arm64InstructionAnalyzer>(this);
}

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
