/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#include "Arm64InstructionAnalyzer.h"

#include <QCoreApplication>

#include <boost/range/size.hpp>

#include <nc/common/CheckedCast.h>
#include <nc/common/Foreach.h>
#include <nc/common/Unreachable.h>
#include <nc/common/make_unique.h>

#include <nc/core/arch/Capstone.h>
#include <nc/core/ir/Program.h>
#include <nc/core/irgen/Expressions.h>
#include <nc/core/irgen/InvalidInstructionException.h>

#include "Arm64Architecture.h"
#include "Arm64Instruction.h"
#include "Arm64Registers.h"
#include <stdlib.h>

namespace nc {
namespace arch {
namespace arm64 {

namespace {

class Arm64ExpressionFactory: public core::irgen::expressions::ExpressionFactory<Arm64ExpressionFactory> {
public:
    Arm64ExpressionFactory(const core::arch::Architecture *architecture):
        core::irgen::expressions::ExpressionFactory<Arm64ExpressionFactory>(architecture)
    {}
};

typedef core::irgen::expressions::ExpressionFactoryCallback<Arm64ExpressionFactory> Arm64ExpressionFactoryCallback;

NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, z)
NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, n)
NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, c)
NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, v)

NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, less)
NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, less_or_equal)
NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, below_or_equal)

NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, sp)
//NC_DEFINE_REGISTER_EXPRESSION(Arm64Registers, pc)

} // anonymous namespace

class Arm64InstructionAnalyzerImpl {
    Q_DECLARE_TR_FUNCTIONS(Arm64InstructionAnalyzerImpl)

    core::arch::Capstone capstone_;
    Arm64ExpressionFactory factory_;
    core::ir::Program *program_;
    const Arm64Instruction *instruction_;
    core::arch::CapstoneInstructionPtr instr_;
    const cs_arm64 *detail_;

public:
    Arm64InstructionAnalyzerImpl(const Arm64Architecture *architecture):
        capstone_(CS_ARCH_ARM64, CS_MODE_ARM), factory_(architecture)
    {}

    void createStatements(const Arm64Instruction *instruction, core::ir::Program *program) {
        assert(instruction != nullptr);
        assert(program != nullptr);

        program_ = program;
        instruction_ = instruction;

        instr_ = disassemble(instruction);
        assert(instr_ != nullptr);
        detail_ = &instr_->detail->arm64;

        auto instructionBasicBlock = program_->getBasicBlockForInstruction(instruction_);

        if (detail_->cc == ARM64_CC_AL) {
            createBody(instructionBasicBlock);
        } else {
            auto directSuccessor = program_->createBasicBlock(instruction_->endAddr());

            auto bodyBasicBlock = program_->createBasicBlock();
            createCondition(instructionBasicBlock, bodyBasicBlock, directSuccessor);
            createBody(bodyBasicBlock);

            if (!bodyBasicBlock->getTerminator()) {
                using namespace core::irgen::expressions;
                Arm64ExpressionFactoryCallback _(factory_, bodyBasicBlock, instruction);
                _[jump(directSuccessor)];
            }
        }
    }

private:
    core::arch::CapstoneInstructionPtr disassemble(const Arm64Instruction *instruction) {
        capstone_.setMode(instruction->csMode());
        return capstone_.disassemble(instruction->addr(), instruction->bytes(), instruction->size());
    }

    void createCondition(core::ir::BasicBlock *conditionBasicBlock, core::ir::BasicBlock *bodyBasicBlock, core::ir::BasicBlock *directSuccessor) {
        using namespace core::irgen::expressions;

        Arm64ExpressionFactoryCallback _(factory_, conditionBasicBlock, instruction_);

        switch (detail_->cc) {
        case ARM64_CC_INVALID:
            throw core::irgen::InvalidInstructionException(tr("Invalid condition code."));
        case ARM64_CC_EQ:
            _[jump( z, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_NE:
            _[jump(~z, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_HS:
            _[jump( c, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_LO:
            _[jump(~c, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_MI:
            _[jump( n, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_PL:
            _[jump(~n, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_VS:
            _[jump( v, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_VC:
            _[jump(~v, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_HI:
            _[jump(~below_or_equal, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_LS:
            _[jump( below_or_equal, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_GE:
            _[jump(~less, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_LT:
            _[jump( less, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_GT:
            _[jump(~less_or_equal, bodyBasicBlock, directSuccessor)];
            break;
        case ARM64_CC_LE:
            _[jump( less_or_equal, bodyBasicBlock, directSuccessor)];
            break;
        default:
            unreachable();
        };
    }

    void createBody(core::ir::BasicBlock *bodyBasicBlock) {
        using namespace core::irgen::expressions;

        Arm64ExpressionFactoryCallback _(factory_, bodyBasicBlock, instruction_);
#if 0
        /*
         * When executing an ARM64 instruction, PC reads as the address of the current instruction plus 8.
         * When executing a Thumb instruction, PC reads as the address of the current instruction plus 4.
         * Writing an address to PC causes a branch to that address.
         */
        _[
            fake_pc ^= constant(instruction_->addr() + 2 * instruction_->size())
        ];
#endif
        switch (instr_->id) {
        case ARM64_INS_ADD: {
            _[operand(0) ^= operand(1) + operand(2)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    _[
                        n ^= signed_(operand(0)) < constant(0),
                        z ^= operand(0) == constant(0),
                        c ^= intrinsic(),
                        v ^= intrinsic(),
                        less ^= ~(n == v),
                        less_or_equal ^= less | z,
                        below_or_equal ^= ~c | z
                    ];
                }
            }
            break;
        }
        case ARM64_INS_AND: {
            _[operand(0) ^= operand(1) & operand(2)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    _[
                        n ^= signed_(operand(0)) < constant(0),
                        z ^= operand(0) == constant(0),
                        c ^= intrinsic(),
                        less ^= ~(n == v),
                        less_or_equal ^= less | z,
                        below_or_equal ^= ~c | z
                    ];
                }
            }
            break;
        }
        case ARM64_INS_B: {
            _[jump(operand(0))];
            break;
        }
        case ARM64_INS_BL: {
            _[call(operand(0))];
            break;
        }
        case ARM64_INS_CMN: {
            _[
                n ^= intrinsic(),
                c ^= unsigned_(operand(0)) < -operand(1),
                z ^= operand(0) == -operand(1),
                v ^= intrinsic(),

                less             ^= signed_(operand(0)) < -operand(1),
                less_or_equal    ^= signed_(operand(0)) <= -operand(1),
                below_or_equal   ^= unsigned_(operand(0)) <= -operand(1)
            ];
            break;
        }
        case ARM64_INS_CMP: {
            _[
                n ^= intrinsic(),
                c ^= unsigned_(operand(0)) < operand(1),
                z ^= operand(0) == operand(1),
                v ^= intrinsic(),

                less             ^= signed_(operand(0)) < operand(1),
                less_or_equal    ^= signed_(operand(0)) <= operand(1),
                below_or_equal   ^= unsigned_(operand(0)) <= operand(1)
            ];
            break;
        }
        case ARM64_INS_EOR: {
            _[operand(0) ^= operand(1) ^ operand(2)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    _[
                        n ^= signed_(operand(0)) < constant(0),
                        z ^= operand(0) == constant(0),
                        c ^= intrinsic(),
                        less ^= ~(n == v),
                        less_or_equal ^= less | z,
                        below_or_equal ^= ~c | z
                    ];
                }
            }
            break;
        }
#if 0
        case ARM64_INS_LDM: {
            auto addr = MemoryLocationExpression(core::ir::MemoryLocation(core::ir::MemoryDomain::LAST_REGISTER, 0, 32));

            _[addr ^= operand(0)];

            for (int i = 1; i < detail_->op_count; ++i) {
                _[operand(i) ^= *(addr + constant(4 * (i - 1)))];
            }
            if (detail_->writeback) {
                _[operand(0) ^= addr + constant(4 * (detail_->op_count - 1))];
            }
            for (int i = 1; i < detail_->op_count; ++i) {
                handleWriteToPC(bodyBasicBlock, i);
            }
            break;
        }
#endif
        case ARM64_INS_LDR: { // TODO: atomic
            _[operand(0) ^= operand(1)];
            handleWriteback(bodyBasicBlock, 1);
            handleWriteToPC(bodyBasicBlock);
            break;
        }
        case ARM64_INS_LDRH: { // TODO: atomic
            _[operand(0) ^= zero_extend(operand(1, 32))];
            handleWriteback(bodyBasicBlock, 1);
            handleWriteToPC(bodyBasicBlock);
            break;
        }
        case ARM64_INS_LDRSH: {
            _[operand(0) ^= sign_extend(operand(1, 32))];
            handleWriteback(bodyBasicBlock, 1);
            handleWriteToPC(bodyBasicBlock);
            break;
        }
        case ARM64_INS_LDRB: { // TODO: atomic
            _[operand(0) ^= zero_extend(operand(1, 8))];
            handleWriteback(bodyBasicBlock, 1);
            handleWriteToPC(bodyBasicBlock);
            break;
        }
        case ARM64_INS_LDRSB: {
            _[operand(0) ^= sign_extend(operand(1, 8))];
            handleWriteback(bodyBasicBlock, 1);
            handleWriteToPC(bodyBasicBlock);
            break;
        }
        case ARM64_INS_LDRSW: {
            _[operand(0) ^= sign_extend(operand(1, 64))];
            handleWriteback(bodyBasicBlock, 1);
            handleWriteToPC(bodyBasicBlock);
            break;
        }
        // TODO case ARM_INS_LDRD:
        case ARM64_INS_MOV: {
            _[operand(0) ^= operand(1)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    // TODO
                }
            }
            break;
        }
#if 0
        case ARM64_INS_MOVT: {
            auto reg = getRegister(getOperandRegister(0));
            auto location = reg->memoryLocation().resized(16).shifted(16);
            _[MemoryLocationExpression(location) ^= operand(1, 16)];
            break;
        }
        case ARM64_INS_MOVW: {
            auto reg = getRegister(getOperandRegister(0));
            auto location = reg->memoryLocation().resized(16);
            _[MemoryLocationExpression(location) ^= operand(1, 16)];
            handleWriteToPC(bodyBasicBlock);
            break;
        }
#endif
        case ARM64_INS_MUL: {
            _[operand(0) ^= operand(1) * operand(2)];
            if (detail_->update_flags) {
                _[
                    n ^= signed_(operand(0)) < constant(0),
                    z ^= operand(0) == constant(0),
                    c ^= intrinsic(),
                    less ^= ~(n == v),
                    less_or_equal ^= less | z,
                    below_or_equal ^= ~c | z
                ];
            }
            break;
        }
        case ARM64_INS_MLA: {
            _[operand(0) ^= operand(1) * operand(2) + operand(3)];
            if (detail_->update_flags) {
                _[
                    n ^= signed_(operand(0)) < constant(0),
                    z ^= operand(0) == constant(0),
                    c ^= intrinsic(),
                    less ^= ~(n == v),
                    less_or_equal ^= less | z,
                    below_or_equal ^= ~c | z
                ];
            }
            break;
        }
        case ARM64_INS_MLS: {
            _[operand(0) ^= operand(1) * operand(2) - operand(3)];
            if (detail_->update_flags) {
                _[
                    n ^= signed_(operand(0)) < constant(0),
                    z ^= operand(0) == constant(0),
                    c ^= intrinsic(),
                    less ^= ~(n == v),
                    less_or_equal ^= less | z,
                    below_or_equal ^= ~c | z
                ];
            }
            break;
        }
#if 0
        case ARM64_INS_MVN: {
            _[operand(0) ^= ~operand(1)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    _[
                        n ^= signed_(operand(0)) < constant(0),
                        z ^= operand(0) == constant(0),
                        c ^= intrinsic(),
                        less ^= ~(n == v),
                        less_or_equal ^= less | z,
                        below_or_equal ^= ~c | z
                    ];
                }
            }
            break;
        }
#endif
        case ARM64_INS_ORR: {
            _[operand(0) ^= operand(1) | operand(2)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    _[
                        n ^= signed_(operand(0)) < constant(0),
                        z ^= operand(0) == constant(0),
                        c ^= intrinsic(),
                        less ^= ~(n == v),
                        less_or_equal ^= less | z,
                        below_or_equal ^= ~c | z
                    ];
                }
            }
            break;
        }
#if 0
        case ARM64_INS_POP: {
            for (int i = 0; i < detail_->op_count; ++i) {
                if (getOperandRegister(i) != ARM64_REG_SP) {
                    _[operand(i) ^= *(sp + constant(4 * i))];
                }
            }
            _[sp ^= sp + constant(4 * detail_->op_count)];
            for (int i = 0; i < detail_->op_count; ++i) {
                handleWriteToPC(bodyBasicBlock, i);
            }
            break;
        }
        case ARM64_INS_PUSH: {
            for (int i = 0; i < detail_->op_count; ++i) {
                _[*(sp - constant(4 * (detail_->op_count - i))) ^= operand(i)];
            }
            _[sp ^= sp - constant(4 * detail_->op_count)];
            break;
        }
        case ARM64_INS_RSB: {
            _[operand(0) ^= operand(2) - operand(1)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    _[
                        n ^= signed_(operand(0)) < constant(0),
                        z ^= operand(0) == constant(0),
                        c ^= intrinsic(),
                        v ^= intrinsic(),
                        less ^= ~(n == v),
                        less_or_equal ^= less | z,
                        below_or_equal ^= ~c | z
                    ];
                }
            }
            break;
        }
        case ARM64_INS_STMDB: {
            for (int i = 1; i < detail_->op_count; ++i) {
                _[*(operand(0) - constant(4 * (detail_->op_count - i - 1))) ^= operand(i)];
            }
            if (detail_->writeback) {
                _[operand(0) ^= operand(0) - constant(4 * (detail_->op_count - 1))];
            }
            break;
        }
#endif
        case ARM64_INS_STR: { // TODO: atomic
            _[operand(1) ^= operand(0)];
            handleWriteback(bodyBasicBlock, 1);
            break;
        }
        case ARM64_INS_STRH: {
            _[operand(1, 32) ^= truncate(operand(0))];
            handleWriteback(bodyBasicBlock, 1);
            break;
        }
        case ARM64_INS_STRB: {
            _[operand(1, 8) ^= truncate(operand(0))];
            handleWriteback(bodyBasicBlock, 1);
            break;
        }
        case ARM64_INS_SUB: {
            _[operand(0) ^= operand(1) - operand(2)];
            if (!handleWriteToPC(bodyBasicBlock)) {
                if (detail_->update_flags) {
                    _[
                        n ^= signed_(operand(0)) < constant(0),
                        z ^= operand(0) == constant(0),
                        c ^= intrinsic(),
                        v ^= intrinsic(),
                        less ^= ~(n == v),
                        less_or_equal ^= less | z,
                        below_or_equal ^= ~c | z
                    ];
                }
            }
            break;
        }
        case ARM64_INS_TST: {
            _[
                n ^= signed_(operand(0) & operand(1)) < constant(0),
                z ^= (operand(0) & operand(1)) == constant(0),
                c ^= intrinsic(),
                less ^= ~(n == v),
                less_or_equal ^= less | z,
                below_or_equal ^= ~c | z
            ];
            break;
        }
        case ARM64_INS_UXTB: {
            _[operand(0) ^= zero_extend(operand(1, 8))];
            break;
        }
        case ARM64_INS_UXTH: {
            _[operand(0) ^= zero_extend(operand(1, 32))];
            break;
        }
        case ARM64_INS_UXTW: {
            _[operand(0) ^= zero_extend(operand(1, 64))];
            break;
        }
        default: {
            _(std::make_unique<core::ir::InlineAssembly>());
            break;
        }
        } /* switch */
    }

    void handleWriteback(core::ir::BasicBlock *bodyBasicBlock, int memOperandIndex) {
        if (detail_->op_count != memOperandIndex + 1 && detail_->op_count != memOperandIndex + 2) {
            throw core::irgen::InvalidInstructionException(tr("Strange number of registers."));
        }
        for (int i = 0; i < memOperandIndex; ++i) {
            if (detail_->operands[i].type != ARM64_OP_REG) {
                throw core::irgen::InvalidInstructionException(tr("Expected the first %1 operand(s) to be register(s).").arg(memOperandIndex));
            }
        }
        if (detail_->operands[memOperandIndex].type != ARM64_OP_MEM) {
            throw core::irgen::InvalidInstructionException(tr("Expected the %1s operand to be a memory operand.").arg(memOperandIndex));
        }

        using namespace core::irgen::expressions;
        Arm64ExpressionFactoryCallback _(factory_, bodyBasicBlock, instruction_);

        if (detail_->op_count == memOperandIndex + 2) {
            auto base = regizter(getRegister(detail_->operands[memOperandIndex].mem.base));
            //if (detail_->operands[memOperandIndex + 1].subtracted) {
            //    _[base ^= base - operand(memOperandIndex + 1)];
            //} else {
                _[base ^= base + operand(memOperandIndex + 1)];
            //}
        } else if (detail_->writeback) {
            auto base = regizter(getRegister(detail_->operands[memOperandIndex].mem.base));
            _[base ^= base + constant(detail_->operands[memOperandIndex].mem.disp)];
        }
    }

    bool handleWriteToPC(core::ir::BasicBlock *bodyBasicBlock, int modifiedOperandIndex = 0) {
        (void)bodyBasicBlock;
        (void)modifiedOperandIndex;
#if 0
        if (getOperandRegister(modifiedOperandIndex) == ARM64_REG_PC) {
            using namespace core::irgen::expressions;
            Arm64ExpressionFactoryCallback _(factory_, bodyBasicBlock, instruction_);

            /*
             * Generate a call instead of a jump for the following code:
             *
             * mov lr, pc
             * ldr pc, [r3]
             *
             * https://github.com/yegord/snowman/issues/22
             */
            if (isReturnAddressSaved(bodyBasicBlock)) {
                _[call(pc)];
            } else {
                _[jump(pc)];
            }
            return true;
        }
#endif
        return false;
    }

    unsigned long fake_pc = 0;

    /*
     * \param bodyBasicBlock Valid pointer to a basic block.
     *
     * \return True iff the last instruction added before the current one
     *         to the basic block is an assignment lr = pc.
     */
    bool isReturnAddressSaved(const core::ir::BasicBlock *bodyBasicBlock) const {
        assert(bodyBasicBlock != nullptr);

        auto begin = bodyBasicBlock->statements().crbegin();
        auto end = bodyBasicBlock->statements().crend();

        while (begin != end && (*begin)->instruction() == instruction_) {
            ++begin;
        }

        if (begin == end) {
            return false;
        }

        auto assignment = (*begin)->asAssignment();
        if (!assignment) {
            return false;
        }

        auto leftAccess = assignment->left()->asMemoryLocationAccess();
        if (!leftAccess) {
            return false;
        }

        if (leftAccess->memoryLocation() != Arm64Registers::x30()->memoryLocation()) {
            return false;
        }

        auto rightAccess = assignment->right()->asMemoryLocationAccess();
        if (!rightAccess) {
            return false;
        }
#if 0
        if (rightAccess->memoryLocation() != Arm64Registers::pc()->memoryLocation()) {
            return false;
        }
#endif
        return true;
    }

    unsigned int getOperandRegister(std::size_t index) const {
        if (index >= detail_->op_count) {
            throw core::irgen::InvalidInstructionException(tr("There is no operand %1.").arg(index));
        }

        const auto &operand = detail_->operands[index];

        if (operand.type == ARM64_OP_REG) {
            return operand.reg;
        } else {
            return ARM64_REG_INVALID;
        }
    }

    core::irgen::expressions::TermExpression operand(std::size_t index, SmallBitSize sizeHint = 32) const {
        assert(index < boost::size(detail_->operands));

        const auto &operand = detail_->operands[index];

        return core::irgen::expressions::TermExpression(createTermForOperand(operand, sizeHint));
    }

    static std::unique_ptr<core::ir::Term> createTermForOperand(const cs_arm64_op &operand, SmallBitSize sizeHint) {
        switch (operand.type) {
            case ARM64_OP_REG:
                return applyShift(operand, std::make_unique<core::ir::MemoryLocationAccess>(
                                               getRegister(operand.reg)->memoryLocation().resized(sizeHint)));
            case ARM64_OP_CIMM:
                throw core::irgen::InvalidInstructionException(tr("Don't know how to deal with CIMM operands."));
            case ARM64_OP_IMM:
                return applyShift(operand, std::make_unique<core::ir::Constant>(SizedValue(sizeHint, operand.imm)));
            case ARM64_OP_FP:
                throw core::irgen::InvalidInstructionException(tr("Don't know how to deal with FP operands."));
            case ARM64_OP_MEM:
                return std::make_unique<core::ir::Dereference>(createDereferenceAddress(operand), core::ir::MemoryDomain::MEMORY, sizeHint);
            default:
                unreachable();
        }
    }

    static std::unique_ptr<core::ir::Term> createDereferenceAddress(const cs_arm64_op &operand) {
        if (operand.type != ARM64_OP_MEM) {
            throw core::irgen::InvalidInstructionException(tr("Expected the operand to be a memory operand"));
        }

        const auto &mem = operand.mem;

        auto result = createRegisterAccess(mem.base);

        if (mem.index != ARM64_REG_INVALID) {
            result = std::make_unique<core::ir::BinaryOperator>(
                core::ir::BinaryOperator::ADD,
                std::move(result),
                createRegisterAccess(mem.index),
                result->size()
            );
        }

        if (mem.disp != 0) {
            result = std::make_unique<core::ir::BinaryOperator>(
                core::ir::BinaryOperator::ADD,
                std::move(result),
                std::make_unique<core::ir::Constant>(SizedValue(result->size(), mem.disp)),
                result->size()
            );
        }

        return applyShift(operand, std::move(result));
    }

    static std::unique_ptr<core::ir::Term> applyShift(const cs_arm64_op &operand, std::unique_ptr<core::ir::Term> result) {
        auto size = result->size();

        switch (operand.shift.type) {
            case ARM64_SFT_INVALID: {
                return result;
            }
            case ARM64_SFT_ASR:{
                return std::make_unique<core::ir::BinaryOperator>(
                    core::ir::BinaryOperator::SAR,
                    std::move(result),
                    createShiftValue(operand),
                    size);
            }
            case ARM64_SFT_LSL:{
                return std::make_unique<core::ir::BinaryOperator>(
                    core::ir::BinaryOperator::SHL,
                    std::move(result),
                    createShiftValue(operand),
                    size);
            }
            case ARM64_SFT_MSL:{
                return std::make_unique<core::ir::BinaryOperator>(
                    core::ir::BinaryOperator::SHL,
                    std::move(result),
                    createShiftValue(operand),
                    size);
            }
            case ARM64_SFT_LSR: {
                return std::make_unique<core::ir::BinaryOperator>(
                    core::ir::BinaryOperator::SHR,
                    std::move(result),
                    createShiftValue(operand),
                    size);
            }
            case ARM64_SFT_ROR: {
                return ror(std::move(result), createShiftValue(operand));
            }
        }
        unreachable();
    }

    static std::unique_ptr<core::ir::Term> ror(std::unique_ptr<core::ir::Term> a, std::unique_ptr<core::ir::Term> b) {
        auto size = a->size();
        auto aa = a->clone();
        auto bb = std::make_unique<core::ir::BinaryOperator>(
            core::ir::BinaryOperator::SUB,
            std::make_unique<core::ir::Constant>(SizedValue(b->size(), size)),
            b->clone(),
            b->size());

        return std::make_unique<core::ir::BinaryOperator>(
            core::ir::BinaryOperator::OR,
                std::make_unique<core::ir::BinaryOperator>(
                    core::ir::BinaryOperator::SHR,
                    std::move(a),
                    std::move(b),
                    size),
                std::make_unique<core::ir::BinaryOperator>(
                    core::ir::BinaryOperator::SHL,
                    std::move(aa),
                    std::move(bb),
                    size),
                size);
    }

    static std::unique_ptr<core::ir::Term> createShiftValue(const cs_arm64_op &operand) {
        switch (operand.shift.type) {
            case ARM64_SFT_INVALID:
                return nullptr;
            case ARM64_SFT_ASR: /* FALLTHROUGH */
            case ARM64_SFT_LSL: /* FALLTHROUGH */
            case ARM64_SFT_LSR: /* FALLTHROUGH */
            case ARM64_SFT_ROR: /* FALLTHROUGH */
            case ARM64_SFT_MSL: {
                return std::make_unique<core::ir::Constant>(SizedValue(sizeof(operand.shift.value) * CHAR_BIT, operand.shift.value));
            }
        }
        unreachable();
    }

    static std::unique_ptr<core::ir::Term> createRegisterAccess(int reg) {
        return Arm64InstructionAnalyzer::createTerm(getRegister(reg));
    }

    static const core::arch::Register *getRegister(int reg) {
        switch (reg) {
        #define REG(lowercase, uppercase) \
            case ARM64_REG_##uppercase: return Arm64Registers::lowercase();
REG(x29,          X29)
REG(x30,          X30)
REG(nzcv,         NZCV)
REG(sp,           SP)
REG(wsp,          WSP)
REG(wzr,          WZR)
REG(xzr,          XZR)

REG(x0,         X0)
REG(x1,         X1)
REG(x2,         X2)
REG(x3,         X3)
REG(x4,         X4)
REG(x5,         X5)
REG(x6,         X6)
REG(x7,         X7)
REG(x8,         X8)
REG(x9,         X9)
REG(x10,         X10)
REG(x11,         X11)
REG(x12,         X12)
REG(x13,         X13)
REG(x14,         X14)
REG(x15,         X15)
REG(x16,         X16)
REG(x17,         X17)
REG(x18,         X18)
REG(x19,         X19)
REG(x20,         X20)
REG(x21,         X21)
REG(x22,         X22)
REG(x23,         X23)
REG(x24,         X24)
REG(x25,         X25)
REG(x26,         X26)
REG(x27,         X27)
REG(x28,         X28)

REG(w0,         W0)
REG(w1,         W1)
REG(w2,         W2)
REG(w3,         W3)
REG(w4,         W4)
REG(w5,         W5)
REG(w6,         W6)
REG(w7,         W7)
REG(w8,         W8)
REG(w9,         W9)
REG(w10,         W10)
REG(w11,         W11)
REG(w12,         W12)
REG(w13,         W13)
REG(w14,         W14)
REG(w15,         W15)
REG(w16,         W16)
REG(w17,         W17)
REG(w18,         W18)
REG(w19,         W19)
REG(w20,         W20)
REG(w21,         W21)
REG(w22,         W22)
REG(w23,         W23)
REG(w24,         W24)
REG(w25,         W25)
REG(w26,         W26)
REG(w27,         W27)
REG(w28,         W28)
REG(w29,         W29)
REG(w30,         W30)


        #undef REG

        default:
            throw core::irgen::InvalidInstructionException(tr("Invalid register number: %1").arg(reg));
        }
    }
};

Arm64InstructionAnalyzer::Arm64InstructionAnalyzer(const Arm64Architecture *architecture):
    impl_(std::make_unique<Arm64InstructionAnalyzerImpl>(architecture))
{}

Arm64InstructionAnalyzer::~Arm64InstructionAnalyzer() {}

void Arm64InstructionAnalyzer::doCreateStatements(const core::arch::Instruction *instruction, core::ir::Program *program) {
    impl_->createStatements(checked_cast<const Arm64Instruction *>(instruction), program);
}

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
