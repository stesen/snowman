/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#pragma once

#include <nc/config.h>

#include <nc/core/irgen/InstructionAnalyzer.h>

namespace nc {
namespace arch {
namespace arm64 {

class Arm64Architecture;
class Arm64InstructionAnalyzerImpl;

class Arm64InstructionAnalyzer: public core::irgen::InstructionAnalyzer {
    std::unique_ptr<Arm64InstructionAnalyzerImpl> impl_;

public:
    Arm64InstructionAnalyzer(const Arm64Architecture *architecture);

    ~Arm64InstructionAnalyzer();

protected:
    virtual void doCreateStatements(const core::arch::Instruction *instruction, core::ir::Program *program) override;
};

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
