/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#include "CallingConventions.h"

#include <nc/common/make_unique.h>
#include <nc/core/ir/Statements.h>
#include <nc/core/ir/Terms.h>

#include "Arm64Architecture.h"
#include "Arm64Registers.h"

namespace nc {
namespace arch {
namespace arm64 {

DefaultCallingConvention::DefaultCallingConvention():
    core::ir::calling::Convention(QLatin1String("Default"))
{
    setStackPointer(Arm64Registers::sp()->memoryLocation());

    setFirstArgumentOffset(0);
    setArgumentAlignment(32);

    std::vector<core::ir::MemoryLocation> args;
    args.push_back(Arm64Registers::r0()->memoryLocation());
    args.push_back(Arm64Registers::r1()->memoryLocation());
    args.push_back(Arm64Registers::r2()->memoryLocation());
    args.push_back(Arm64Registers::r3()->memoryLocation());
    addArgumentGroup(std::move(args));

    addReturnValueLocation(Arm64Registers::r0()->memoryLocation());

    addEnterStatement(std::make_unique<core::ir::Assignment>(
        std::make_unique<core::ir::MemoryLocationAccess>(Arm64Registers::lr()->memoryLocation()),
        std::make_unique<core::ir::Intrinsic>(core::ir::Intrinsic::RETURN_ADDRESS, Arm64Registers::lr()->size())
    ));
}

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
