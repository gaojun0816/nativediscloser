from angr.sim_type import register_types, parse_type

from . import JNI_PROCEDURES
from .common import NotImplementedJNIFunction
from .jni_invoke import jni_invoke_interface as jvm
from .jni_native import jni_native_interface as jenv


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


