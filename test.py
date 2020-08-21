import angr
import cle
import logging
from androguard.misc import AnalyzeAPK

from jni_interfaces.utils import (record_static_jni_functions, clean_records,
        record_dynamic_jni_functions, print_records, JNI_LOADER)

APK = 'so4test/app-release.apk'
BIN = 'so4test/libnative-lib.so'
# BIN = 'so4test/libcms.so'
SO_DIR = 'lib/armeabi-v7a/'


# logging.disable(level=logging.CRITICAL)


def run():
    apk, _, dex = AnalyzeAPK(APK)
    class_names = [refactor_cls_name(n) for n in dex.classes.keys()]
    with apk.zip as zf:
        for n in zf.namelist():
            if n.startswith(SO_DIR) and n.endswith('.so'):
                with zf.open(n) as so_file:
                    find_all_jni_functions(so_file, class_names)
                    print('='*50, n)
                    print_records()
                    #TODO analysis jni functions for cross invocations


def refactor_cls_name(raw_name):
    return raw_name.lstrip('L').rstrip(';').replace('/', '.')


def find_all_jni_functions(so_file, class_names):
    cle_loader = cle.loader.Loader(so_file, auto_load_libs=False)
    proj = angr.Project(cle_loader)
    clean_records()
    record_static_jni_functions(proj, class_names)
    if proj.loader.find_symbol(JNI_LOADER):
        record_dynamic_jni_functions(proj)


if __name__ == '__main__':
    run()

