import claripy
import archinfo
from angr.procedures.java_jni import JNISimProcedure as JSP



class JNIEnvMissingError(Exception):
    pass


class GetEnv(JSP):
    return_ty = 'int'

    def run(self, jvm, env, version, env_ptr=None):
        print('GetEnv', jvm)
        if env_ptr:
            self.state.memory.store(env, env_ptr, endness=archinfo.Endness.LE)
        else:
            raise JNIEnvMissingError('Pass the JNI native function table \
                    pointer as a kwarg with name "env_ptr"!')
        JNI_OK = claripy.BVV(0, self.arch.bits)
        return JNI_OK

