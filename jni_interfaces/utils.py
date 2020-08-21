import sys
from angr.sim_type import register_types, parse_type

from . import JNI_PROCEDURES
from .common import NotImplementedJNIFunction
from .jni_invoke import jni_invoke_interface as jvm
from .jni_native import jni_native_interface as jenv
from .record import Record

JNI_LOADER = 'JNI_OnLoad'


def record_static_jni_functions(proj, cls_list):
    """record the statically exported JNI functions
    The strategy is to 1st find the symbol names started with 'Java',
    2nd verify the truth of JNI function by check the class part of the name
    with classes in the 'cls_list' which is from dex files of the APK.
    """
    for s in proj.loader.symbols:
        if s.name.startswith('Java'):
            cls_name, method_name = extract_names(s.name)
            if cls_name in cls_list:
                func_ptr = s.rebased_addr
                Record(cls_name, method_name, None, func_ptr, s.name, True)


def extract_names(symbol):
    """Extract class and method name from exported JNI function symbol name
    The assumption is that the pattern of the exported JNI function symbol is
    1. start with 'Java', 2. followed by the seperated full class name 3. end
    with the method name, 4. all parts are seperated by '_'.
    """
    parts = symbol.split('_')
    method_name = parts[-1]
    cls_name = '.'.join(parts[1:-1])
    return cls_name, method_name


def record_dynamic_jni_functions(proj):
    jvm_ptr, jenv_ptr = jni_env_prepare_in_object(proj)
    func_jni_onload = proj.loader.find_symbol(JNI_LOADER)
    state = proj.factory.blank_state(addr=func_jni_onload.rebased_addr)
    jni_env_prepare_in_state(state, jvm_ptr, jenv_ptr)
    simgr = proj.factory.simgr(state)
    simgr.run()


def jni_env_prepare_in_object(proj):
    jni_addr_size = proj.arch.bits // 8
    jvm_size = jni_addr_size * len(jvm)
    jenv_size = jni_addr_size * len(jenv)
    jvm_ptr = proj.loader.extern_object.allocate(jvm_size)
    jenv_ptr = proj.loader.extern_object.allocate(jenv_size)
    for idx, name in enumerate(jvm):
        addr = jvm_ptr + idx * jni_addr_size
        try_2_hook(name, proj, addr)
    for idx, name in enumerate(jenv):
        addr = jenv_ptr + idx * jni_addr_size
        try_2_hook(name, proj, addr)
    register_jni_relevant_data_type()
    return jvm_ptr, jenv_ptr


def try_2_hook(jni_func_name, proj, addr):
    proc = JNI_PROCEDURES.get(jni_func_name)
    if proc:
        proj.hook(addr, proc())
    else:
        proj.hook(addr, NotImplementedJNIFunction())


def jni_env_prepare_in_state(state, jvm_ptr, jenv_ptr):
    state.regs.r0 = state.solver.BVV(jvm_ptr, state.project.arch.bits)
    # store JVM and JENV pointer on the state for global use
    state.globals['jvm_ptr'] = jvm_ptr
    state.globals['jni_invoke_interface'] = jvm
    state.globals['jenv_ptr'] = jenv_ptr
    state.globals['jni_native_interface'] = jenv
    addr_size = state.project.arch.bits
    for idx in range(len(jvm)):
        jvm_func_addr = jvm_ptr + idx * addr_size // 8
        state.memory.store(addr=jvm_func_addr,
                           data=state.solver.BVV(jvm_func_addr, addr_size),
                           endness=state.project.arch.memory_endness)
    for idx in range(len(jenv)):
        jenv_func_addr = jenv_ptr + idx * addr_size // 8
        state.memory.store(addr=jenv_func_addr,
                           data=state.solver.BVV(jenv_func_addr, addr_size),
                           endness=state.project.arch.memory_endness)


def register_jni_relevant_data_type():
    register_types(parse_type('struct JNINativeMethod ' +\
                              '{const char* name;' +\
                              'const char* signature;' +\
                              'void* fnPtr;}'))


def print_records(file=sys.stdout):
    header = 'invoker_cls, invoker_method, invoker_signature, invoker_symbol, ' +\
             'invoker_static_export, ' +\
             'invokee_cls, invokee_method, invokee_signature, invokee_static'
    print(header, file=file)
    for _, r in Record.RECORDS.items():
        print(r, file=file)


def clean_records():
    Record.RECORDS = dict()

