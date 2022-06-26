import os
from typing import Optional

import binaryninja as bn
from binaryninja import BinaryView, TypeLibrary


def get_library_path() -> Optional[str]:
    library_path = bn.TextLineField("Path to load type library:", "~/Desktop/libc.bntl")
    bn.get_form_input([library_path], "Apply Type Library Options")

    if os.path.exists(os.path.expanduser(library_path.result)):
        return library_path.result
    else:
        return None


def apply_library(bv: BinaryView, typelib_handle: TypeLibrary):
    exported_objs = typelib_handle.named_objects
    for qual_name, exported_type in exported_objs.items():
        print(f"qual_name: {str(qual_name)} | type: {str(exported_type)}")
    return


def load_library(bv: BinaryView):
    lib_path = get_library_path()
    if lib_path is None:
        bn.log_error(f"Supplied path was invalid")
        return
    typelib_handle = TypeLibrary.load_from_file(lib_path)
    bv.add_type_library(typelib_handle)
    apply_library(bv, typelib_handle)
    return
