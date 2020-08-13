import os
from angr import SIM_PROCEDURES
from angr.procedures.java_jni import jni_functions as jenv

from . import JNI_PROCEDURES
from .jni_invoke import jni_invoke_interface as jvm


def jni_env_prepare(proj):
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
    return jvm_ptr


def try_2_hook(jni_func_name, proj, addr):
    local_proc = JNI_PROCEDURES.get(jni_func_name)
    if local_proc:
        proj.hook(addr, local_proc())
    else:
        angr_proc = SIM_PROCEDURES['java_jni'].get(jni_func_name)
        if angr_proc:
            proj.hook(addr, angr_proc())
        else:
            unsupport_proc = SIM_PROCEDURES['java_jni'].get('UnsupportedJNIFunction')
            proj.hook(addr, unsupport_proc())



