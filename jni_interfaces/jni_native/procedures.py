import archinfo
from ..common import JNIProcedureBase as JPB
from ..common import JNIEnvMissingError
from ..record import Record


class FindClass(JPB):
    def run(self, env_ptr, cls_name_ptr):
        cls_name = self.load_string_from_memory(cls_name_ptr)
        return self.create_java_class(cls_name)


class RegisterNatives(JPB):
    def run(self, env, cls_ptr, methods, method_num):
        cls_name = self.get_java_class(cls_ptr).name
        num = self.state.solver.eval(method_num)
        methods_ptr = self.state.solver.eval(methods)
        for i in range(num):
            ptr = methods_ptr + i * 3 * self.arch.bits // 8
            method = self.state.mem[ptr].struct.JNINativeMethod
            name = method.name.deref.string.concrete
            signature = method.signature.deref.string.concrete
            fn_ptr = method.fnPtr.long.concrete
            func_name = self.func_ptr_2_symbol_name(fn_ptr)
            Record(cls_name, name.decode('utf-8', 'ignore'),
                   signature.decode('utf-8', 'ignore'), fn_ptr, func_name)
        return self.JNI_OK

    def func_ptr_2_symbol_name(self, func_ptr):
        name = None
        for s in self.state.project.loader.symbols:
            if s.rebased_addr == func_ptr:
                name = s.name
        return name


