from angr.simos import SimOS, register_simos
from angr.sim_procedure import SimProcedure
from angr.calling_conventions import (
    SimStackArg,
    SimRegArg,
    SimCC,
    register_syscall_cc,
    register_default_cc,
    SimCC,
)
from archinfo.arch_riscv64 import ArchRISCV64


class SimCCRISCV(SimCC):
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5"]
    FP_ARG_REGS = []  # expand in case the floating point extension is added
    STACK_ALIGNMENT = 16
    RETURN_ADDR = SimRegArg("ra", 8)
    RETURN_VAL = SimRegArg("a0", 8)
    ARCH = ArchRISCV64


class SimRISCVSyscall(SimCC):
    ARG_REGS = ["a0", "a1", "a2", "a3", "a4", "a5"]
    RETURN_VAL = SimRegArg("a0", 8)
    RETURN_ADDR = SimStackArg(8, 8)
    ARCH = ArchRISCV64

    @staticmethod
    def _match(arch, args, sp_delta):  # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        return state.regs.a7


register_syscall_cc("RISCV64", "Linux", SimRISCVSyscall)
register_default_cc("RISCV64", SimCCRISCV)
