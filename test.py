import angr
import logging

from jni_interfaces.utils import (jni_env_prepare_in_object,
        jni_env_prepare_in_state, print_records)

# BIN = 'so4test/libnative-lib.so'
BIN = 'so4test/libcms.so'
JNI_LOADER = 'JNI_OnLoad'


# logging.disable(level=logging.CRITICAL)


def test():
    proj = angr.Project(BIN, auto_load_libs=False)
    jvm_ptr, jenv_ptr = jni_env_prepare_in_object(proj)
    # print(proj._sim_procedures)
    func_jni_onload = proj.loader.find_symbol(JNI_LOADER)
    state = proj.factory.blank_state(addr=func_jni_onload.rebased_addr)
    jni_env_prepare_in_state(state, jvm_ptr, jenv_ptr)
    simgr = proj.factory.simgr(state)
    simgr.run()
    print_records()


if __name__ == '__main__':
    test()

