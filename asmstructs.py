import idc
import re
from sympy import Symbol, Integer
from ctypes import c_int64
from debugprint import printf

class operand():
    def __init__(self, name, op_type, value):
        from sympy.parsing.sympy_parser import parse_expr
        self.name = name
        self.type = op_type
        if self.type == idc.o_displ:
            self.value = re.split('\s*,\s*', name.strip('][').replace('#', '').replace('@', '_'))
            self.value = [parse_expr(op) for op in self.value]
            self.value = self.value[0] + c_int64(value).value
        elif self.type == idc.o_imm:
            self.value = parse_expr(name.replace('#', '').replace('@', '_'))
            self.value = value
        elif self.type in [idc.o_reg, idc.o_idpspec0]:
            if self.name in ['WZR', 'XZR']:
                self.value = Integer(0)
            else:
                self.value = Symbol(self.name)
        else:
            self.value = value
    
    def __str__(self):
        if self.type == idc.o_imm:
            result = str(self.value)
        elif self.type in [idc.o_far, idc.o_near]:
            result = '%08x'%self.value
        elif self.type == idc.o_displ:
            result = str(self.value)
        else:
            result = str(self.value)
        return result

    def __repr__(self):
        return self.__str__()


class command():
    def __init__(self, name, ea):
        self.name = name
        self.ea = ea
        self.operands = []

    def op_append(self, value):
        self.operands.append(value)

    def __str__(self):
        return '%08x:   %-4s    '%(self.ea, self.name) + str(self.operands)

    def __repr__(self):
        return self.__str__()