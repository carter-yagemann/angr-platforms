from .instruction_patterns import RISCV_Instruction, CSS_Instruction
from pyvex.lifting.util import Type, Instruction, ParseError
from bitstring import BitArray

class Instruction_CSWSP(CSS_Instruction):
    opcode = '10'
    func3 = '110'
    name = 'CSWSP'

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def fetch_operands(self):
        return (self.get_src1(),)

    def get_imm(self):
        val = "{0}{1}00".format(self.data['i'][4:6], self.data['i'][0:4])
        res = self.constant(BitArray(bin=val).int, Type.int_64)
        return res

    def compute_result(self, src1):
        return src1

    def commit_result(self, result):
        self.store(result, self.get(2, Type.int_64) + self.get_imm())


class Instruction_CSDSP(CSS_Instruction):
    opcode = '10'
    func3 = '111'
    name = 'CSDSP'

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_64)

    def fetch_operands(self):
        return (self.get_src1(),)

    def get_imm(self):
        val = "{0}{1}000".format(self.data['i'][3:6], self.data['i'][0:3])
        res = self.constant(BitArray(bin=val).int, Type.int_64)
        return res

    def compute_result(self, src1):
        return src1

    def commit_result(self, result):
        self.store(result, self.get(2, Type.int_64) + self.get_imm())
