import re
import logging
import itertools
from angr import SimProcedure
from .record import Record

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class JNIProcedureBase(SimProcedure):
    # constants used in JNI
    JNI_OK = 0
    JNI_FALSE = 0
    JNI_TRUE = 1

    def load_string_from_memory(self, addr):
        """
        Load zero terminated string from memory.

        Params:
        addr: address to start the loading of the string.

        Return:
        the string.
        """
        solved_addr = self.state.solver.eval(addr)

        # load chars until terminator 0 is met
        chars = list()
        for i in itertools.count():
            str_byte = self.state.memory.load(solved_addr+i, size=1)
            solved_str = self.state.solver.eval(str_byte)
            if solved_str == 0:
                break
            chars.append(chr(solved_str))

        return "".join(chars)

    def set_class_field(self, class_name, field_name, value):
        return self.set_object_field("##class##"+class_name, field_name, value)

    def get_class_field(self, class_name, field_name):
        return self.get_object_field("##class##"+class_name, field_name)

    def set_object_field(self, obj_symb, field_name, new_value):
        (obj, old_value) = self.get_object_field(obj_symb, field_name) # Ensure the creation of the field
        obj[field_name] = new_value
        return old_value

    def get_object_field(self, obj_symb, field_name):
        obj = self.create_java_object(obj_symb)
        if field_name not in obj:
            # TODO: Use the type of the field for typing of the symbol
            obj[field_name] = self.state.solver.BVS("##field##%s" % field_name, self.arch.bits)
        return (obj, obj[field_name])

    def create_java_object(self, obj_symb):
        obj_symb_str = str(obj_symb)
        if obj_symb_str not in self.state.globals:
            self.state.globals[obj_symb_str] = {}
        return self.state.globals[obj_symb_str]

    def create_field(self, obj, field, desc=""):
        symb_name = desc if desc else 'field_value'
        field_symbol = self.state.solver.BVS(symb_name, self.arch.bits)
        # self.state.add_constraints(field_symbol == ref)
        return field_symbol

    def create_java_class(self, cls_name, init=False, desc=None):
        ref = self.state.project.loader.extern_object.allocate()
        jcls = JavaClass(cls_name, init, desc)
        self.state.globals[ref] = jcls

        symb_name = desc if desc else 'jobject_value'
        obj_symbol = self.state.solver.BVS(symb_name, self.arch.bits)
        self.state.add_constraints(obj_symbol == ref)
        return obj_symbol

    def create_java_method_ID(self, cls, name, signature, static=False):
        ref = self.state.project.loader.extern_object.allocate()
        jmethod = JavaMethod(cls, name, signature, static)
        self.state.globals[ref] = jmethod

        method_symbol = self.state.solver.BVS('jmethod_value', self.arch.bits)
        self.state.add_constraints(method_symbol == ref)
        return method_symbol

    def create_java_field_ID(self, cls, name, ftype, static=False):
        ref = self.state.project.loader.extern_object.allocate()
        jfield = JavaField(cls, name, ftype)
        self.state.globals[ref] = jfield

        field_symbol = self.state.solver.BVS('jfield_value', self.arch.bits)
        self.state.add_constraints(field_symbol == ref)
        return field_symbol

    def get_ref(self, raw_ref):
        ref = self.state.solver.eval(raw_ref)
        return self.state.globals.get(ref)

    def get_current_record(self):
        func_ptr = self.state.globals.get('func_ptr')
        return Record.RECORDS.get(func_ptr)


class NotImplementedJNIFunction(JNIProcedureBase):
    def run(self):
        symbol_name = self._get_symbol_name()
        logger.warning(f'"{symbol_name}" is called as Not implemented JNI procedure')
        return self.state.solver.Unconstrained(symbol_name, self.state.arch.bits)

    def _get_symbol_name(self):
        symbol_name = None
        func_size = self.state.arch.bits // 8
        addr = self.state.addr
        jvm_start_ptr = self.state.globals.get('jvm_ptr')
        jvm = self.state.globals.get('jni_invoke_interface')
        jenv_start_ptr = self.state.globals.get('jenv_ptr')
        jenv = self.state.globals.get('jni_native_interface')
        if jvm_start_ptr is None:
            raise JNIEvnMissingError('"jvm_ptr" is not stored in state')
        if jvm is None:
            raise JNIEvnMissingError('"jni_invoke_interface" is not stored in state')
        if jenv_start_ptr is None:
            raise JNIEvnMissingError('"jenv_ptr" is not stored in state')
        if jenv is None:
            raise JNIEvnMissingError('"jni_native_interface" is not stored in state')
        jvm_end_ptr = jvm_start_ptr + len(jvm) *  func_size
        jenv_end_ptr = jenv_start_ptr + len(jenv) * func_size
        if jvm_start_ptr <= addr <= jvm_end_ptr:
            func_idx = (addr - jvm_start_ptr) // func_size
            symbol_name = jvm[func_idx]
        elif jenv_start_ptr <= addr <= jenv_end_ptr:
            func_idx = (addr - jenv_start_ptr) // func_size
            symbol_name = jenv[func_idx]
        else:
            logger.warning('None JNI function address passed to JNI procedure')
        return symbol_name


class JavaClass:
    def __init__(self, name, init=False, desc=None, is_array=False):
        self.name = name
        self.init = init
        self.desc = desc
        self.is_array = is_array

    def __str__(self):
        return self.name


class JavaField:
    def __init__(self, cls, name, ftype):
        self.cls = cls
        self.name = name
        self.ftype = ftype

    def __str__(self):
        return f'<JavaField: {self.ftype} {self.name} of class {self.cls}>'


class JavaMethod:
    def __init__(self, cls, name, signature, static=False):
        self.cls = cls
        self.name = name
        self.signature = signature
        self.static = static

    def get_return_type(self):
        pat = r'^\([\w\d[/;$]*\)(?P<rtype>[\w\d[/;$]+)$'
        return re.match(pat, self.signature).group('rtype')

    def __str__(self):
        return f'<JavaMethod: {self.name} {self.signature} of class {self.cls}>'


class JNIEnvMissingError(Exception):
    pass

