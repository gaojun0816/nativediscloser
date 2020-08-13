import os
import angr

from jni_interfaces.utils import jni_env_prepare

BIN = 'so4test/libnative-lib.so'
JNI_LOADER = 'JNI_OnLoad'

# create the project
proj = angr.Project(BIN)

def get_all_libs():
    libs = list()
    for f in os.listdir():
        if os.path.isfile(f) and f.endswith('so'):
            libs.append(f)
    return libs


def test():
    proj = angr.Project(BIN, auto_load_libs=False)
    jvm_ptr = jni_env_prepare(proj)
    print(hex(jvm_ptr))
    # print(proj._sim_procedures)
    func_jni_onload = proj.loader.find_symbol(JNI_LOADER)
    state = proj.factory.blank_state(addr=func_jni_onload.rebased_addr)
    # state = proj.factory.full_init_state(addr=func_jni_onload.rebased_addr)
    state.regs.r0 = state.solver.BVV(jvm_ptr, proj.arch.bits)
    # state.step()
    simgr = proj.factory.simgr(state)
    simgr.run()


if __name__ == '__main__':
    test()

