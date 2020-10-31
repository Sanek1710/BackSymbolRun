from idc import *
from idautils import *
import arm


class stack():
    def __init__(self, ea):
        self.frame_size = int(get_frame_size(ea))
        self.members = [[int(offs - self.frame_size), name, int(size)] for offs, name, size in StructMembers(get_frame_id(ea))]
        if self.members:
            if self.members[0][0] != -self.frame_size:
                self.members.insert(0, [-self.frame_size, 'SP_local', self.members[0][0] + self.frame_size])
        else:
            self.members.append([-self.frame_size, 'SP_local', self.frame_size])
        for item in self.members:
            print(item)
        
    def member_size(self, offset):
        if offset > 0:
            return None
        
        for memb_offs, _, _ in self.members:
            if memb_offs > offset:
                return memb_offs - offset
        return 0

    def print_list_generator(self):
        i = -self.frame_size + 1
        out_strs = []
        out_str = '%-10s: |'%(arm.SP - self.frame_size)
        sm_n = 0
        for item in self.members:
            for b in range(item[2]):
                out_str += '%c|'%chr(ord('a') + sm_n)
                if i % 16 == 0:
                    out_strs.append(out_str)
                    out_str = '%-10s: |'%(arm.SP + i)
                i += 1
            sm_n += 1

        if i % 16 != 1:
            for j in range(i % 16 - 1):
                out_str += ' |'
            out_strs.append(out_str)

        return reversed(out_strs)

    def print_table_generator(self):
        result = []
        result.append('| offset |   variable name   |  size  |  *  |')
        i = 0
        for offs, name, size in self.members:
            result.append('| %6d | %-17s | %6d |  %c  |'%(offs, name, size, chr(ord('a') + i)))
            i += 1
        return result

    def __str__(self):
        res_str = '| offset |   variable name   |  size  |  *  |\n'
        i = len(self.members) - 1
        for offs, name, size in self.members:
            res_str += '| %6d | %-17s | %6d |  %c  |\n'%(offs, name, size, chr(ord('a') + i))
            i -= 1
        return res_str

    def __repr__(self):
        return self.__str__()