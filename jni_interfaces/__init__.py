import importlib
from angr.procedures.java_jni import JNISimProcedure as JSP

JNI_PROCEDURES = dict()


def find_simprocs(module_name, container):
    module = importlib.import_module(module_name, 'jni_interfaces')
    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if isinstance(attr, type) and issubclass(attr, JSP):
            container.update({attr_name: attr})


find_simprocs('.jni_invoke', JNI_PROCEDURES)
find_simprocs('.jni_native', JNI_PROCEDURES)



