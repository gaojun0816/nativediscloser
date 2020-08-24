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
        cls_name = self.get_ref(cls_ptr).name
        num = self.state.solver.eval(method_num)
        methods_ptr = self.state.solver.eval(methods)
        for i in range(num):
            ptr = methods_ptr + i * 3 * self.arch.bits // 8
            method = self.state.mem[ptr].struct.JNINativeMethod
            name = method.name.deref.string.concrete
            signature = method.signature.deref.string.concrete
            fn_ptr = method.fnPtr.long.concrete
            func_name = self.func_ptr_2_symbol_name(fn_ptr)
            Record(cls_name.replace('/', '.'), name.decode('utf-8', 'ignore'),
                   signature.decode('utf-8', 'ignore'), fn_ptr, func_name)
        return self.JNI_OK

    def func_ptr_2_symbol_name(self, func_ptr):
        name = None
        for s in self.state.project.loader.symbols:
            if s.rebased_addr == func_ptr:
                name = s.name
        return name


class GetObjectClass(JPB):
    def run(self, env, obj):
        desc = 'jclass obtained via "GetObjectClass" which cannot be parsed'
        return self.create_java_class(None, desc=desc)


class GetMethodBase(JPB):
    def run(self, env, cls_ptr, method_name_ptr, sig_ptr):
        cls = self.get_ref(cls_ptr)
        method_name = self.load_string_from_memory(method_name_ptr)
        signature = self.load_string_from_memory(sig_ptr)
        return self.create_java_method_ID(cls, method_name,
                signature, self.is_static())

    def is_static(self):
        raise NotImplementedError('"is_static" need to be implemented!')


class GetStaticMethodID(GetMethodBase):
    def is_static(self):
        return True


class GetMethodID(GetMethodBase):
    def is_static(self):
        return False


class CallMethodBase(JPB):
    def run(self, env, _, method_ptr):
        method = self.get_ref(method_ptr)
        record = self.get_current_record()
        record.add_invokee(method)
        return_value = self.get_return_value()
        if return_value:
            return return_value

    def get_current_record(self):
        func_ptr = self.state.globals.get('func_ptr')
        return Record.RECORDS.get(func_ptr)

    def get_return_value(self):
        raise NotImplementedError('Extending CallMethodBase without implement get_return_value!')


class CallPrimeMethod(CallMethodBase):
    def get_return_value(self):
        return self.state.solver.BVS('prime_value', self.arch.bits)


class CallVoidMethod(CallMethodBase):
    def get_return_value(self):
        return None


class CallObjectMethod(CallMethodBase):
    def get_return_value(self):
        desc = 'jobject returned from "CallObjectMethod" which cannot be parsed'
        return self.create_java_class(None, init=True, desc=desc)


class CallObjectMethodV(CallObjectMethod):
    pass


class CallStaticVoidMethod(CallVoidMethod):
    pass


class CallStaticVoidMethodV(CallVoidMethod):
    pass
