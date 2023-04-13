# pylint: disable=W0613,R0201,W0221
from pyvex.lifting.util import Type
from .instruction_patterns import R_Instruction

class Instruction_ADD(R_Instruction):
    func3 = '000'
    func7 = '0000000'
    opcode = '0110011'
    name = 'ADD'

    def compute_result(self, src1, src2):
        return src1 + src2


class Instruction_ADDW(R_Instruction):
    func3 = '000'
    func7 = '0000000'
    opcode = '0111011'
    name = 'ADDW'

    def compute_result(self, src1, src2):
        return ((src1 + src2) & 0xffffffff).cast_to(Type.int_64, signed=True)


class Instruction_SUB(R_Instruction):
    func3 = '000'
    func7 = '0100000'
    opcode = '0110011'
    name = 'SUB'

    def compute_result(self, src1, src2):
        return src1 - src2


class Instruction_SUBW(R_Instruction):
    func3 = '000'
    func7 = '0100000'
    opcode = '0111011'
    name = 'SUBW'

    def compute_result(self, src1, src2):
        return ((src1 - src2) & 0xffffffff).cast_to(Type.int_64, signed=True)


class Instruction_XOR(R_Instruction):
    func3 = '100'
    func7 = '0000000'
    opcode = '0110011'
    name= 'XOR'

    def compute_result(self, src1, src2):
        return src1 ^ src2


class Instruction_OR(R_Instruction):
    func3 = '110'
    func7 = '0000000'
    opcode = '0110011'
    name = 'OR'

    def compute_result(self, src1, src2):
        return src1 | src2


class Instruction_AND(R_Instruction):
    func3 = '111'
    func7 = '0000000'
    opcode = '0110011'
    name = 'AND'

    def compute_result(self, src1, src2):
        return src1 & src2


class Instruction_SLL(R_Instruction):
    func3 = '001'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SLL'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'], 2), Type.int_8)[5:] #RV64 USES ONLY THE LOW 6 BITS OF RS2
        return (src1 << shftamnt) & self.constant(0xffffffffffffffff, Type.int_64)


class Instruction_SRL(R_Instruction):
    func3 = '101'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SRL'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'], 2), Type.int_8)[5:] #RV64 USES ONLY THE LOW 6 BITS OF RS2
        return ((src1 % 0x10000000000000000) >> shftamnt) & self.constant(0xffffffffffffffff, Type.int_64)


class Instruction_SRA(R_Instruction):
    func3 = '101'
    func7 = '0100000'
    opcode = '0110011'
    name = 'SRA'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'], 2), Type.int_8)[5:] #RV64 USES ONLY THE LOW 6 BITS OF RS2
        return (src1 >> shftamnt) & self.constant(0xffffffff, Type.int_32)

class Instruction_SLLW(R_Instruction):
    func3 = '001'
    func7 = '0000000'
    opcode = '0111011'
    name = 'SLLW'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'], 2), Type.int_8)[4:]
        return ((src1 & self.constant(0xffffffff, Type.int_32)) << shftamnt) & self.constant(0xffffffff, Type.int_32)


class Instruction_SRLW(R_Instruction):
    func3 = '101'
    func7 = '0000000'
    opcode = '0111011'
    name = 'SRLW'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'], 2), Type.int_8)& self.constant(0b11111, Type.int_8)
        return (((src1 & self.constant(0xffffffff, Type.int_32)) % 0x100000000) >> shftamnt) & self.constant(0xffffffff, Type.int_32)


class Instruction_SRAW(R_Instruction):
    func3 = '101'
    func7 = '0100000'
    opcode = '0111011'
    name = 'SRAW'

    def compute_result(self, src1, src2):
        shftamnt = self.get(int(self.data['S'], 2), Type.int_8)& self.constant(0b11111, Type.int_8)
        return ((src1 & self.constant(0xffffffff, Type.int_32)) >> shftamnt) & self.constant(0xffffffff, Type.int_32)

class Instruction_SLT(R_Instruction):
    func3 = '010'
    func7 = '0000000'
    opcode = '0110011'
    name='SLT'

    def compute_result(self, src1, src2):
        src1.is_signed = True
        src2.is_signed = True
        val = 1 if src1 < src2 else 0
        return self.constant(val, Type.int_64)


class Instruction_SLTU(R_Instruction):
    func3 = '011'
    func7 = '0000000'
    opcode = '0110011'
    name = 'SLTU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src1.is_signed = False
        val = 1 if src1 < src2 else 0
        return self.constant(val, Type.int_64)


class Instruction_MUL(R_Instruction):
    func3='000'
    func7='0000001'
    opcode='0110011'
    name='MUL'

    def compute_result(self, src1, src2):
        return (src1 * src2) & self.constant(0xffffffffffffffff, Type.int_64)

class Instruction_MULH(R_Instruction):
    func3='001'
    func7='0000001'
    opcode='0110011'
    name='MULH'

    def compute_result(self, src1, src2):
        return (src1 * src2) >> self.constant(64, Type.int_8)

class Instruction_MULSU(R_Instruction):
    func3='010'
    func7='0000001'
    opcode='0110011'
    name='MULSU'

    def compute_result(self, src1, src2):
        src1 = src1.signed
        src2.is_signed = False
        return (src1 * src2) & self.constant(0xffffffffffffffff, Type.int_64)

class Instruction_MULHU(R_Instruction):
    func3='011'
    func7='0000001'
    opcode='0110011'
    name='MULHU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return (src1 * src2) >> self.constant(64, Type.int_8)

class Instruction_MULW(R_Instruction):
    func3='000'
    func7='0000001'
    opcode='0111011'
    name='MULW'

    def compute_result(self, src1, src2):
        return ((src1 * src2) & 0xffffffff).cast_to(Type.int_64, signed=True)

class Instruction_DIV(R_Instruction):
    func3='100'
    func7='0000001'
    opcode='0110011'
    name='DIV'

    def compute_result(self, src1, src2):
        src1 = src1.signed
        src2 = src2.signed
        return src1 // src2

class Instruction_DIVU(R_Instruction):
    func3='101'
    func7='0000001'
    opcode='0110011'
    name='DIVU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return src1 // src2

class Instruction_DIVW(R_Instruction):
    func3='100'
    func7='0000001'
    opcode='0111011'
    name='DIVW'

    def compute_result(self, src1, src2):
        return (((src1.signed & 0xffffffff) // (src2.signed & 0xffffffff, Type.int_32)) & 0xffffffff).cast_to(Type.int_64, signed=True)

class Instruction_DIVUW(R_Instruction):
    func3='101'
    func7='0000001'
    opcode='0111011'
    name='DIVUW'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return (((src1 & 0xffffffff) // (src2 & 0xffffffff)) & 0xffffffff).cast_to(Type.int_64, signed=True)

class Instruction_REM(R_Instruction):
    func3='110'
    func7='0000001'
    opcode='0110011'
    name='REM'

    def compute_result(self, src1, src2):
        return src1.signed % src2.signed

class Instruction_REMU(R_Instruction):
    func3='111'
    func7='0000001'
    opcode='0110011'
    name ='REMU'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return src1 % src2

class Instruction_REMW(R_Instruction):
    func3='110'
    func7='0000001'
    opcode='0111011'
    name='REMW'

    def compute_result(self, src1, src2):
        return (((src1.signed & 0xffffffff) % (src2.signed & 0xffffffff)) & 0xffffffff).cast_to(Type.int_64, signed=True)

class Instruction_REMUW(R_Instruction):
    func3='111'
    func7='0000001'
    opcode='0111011'
    name='REMUW'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return (((src1 & 0xffffffff) % (src2 & 0xffffffff)) & 0xffffffff).cast_to(Type.int_64, signed=True)
