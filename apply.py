import os
from typing import Optional

import binaryninja as bn
from binaryninja import BinaryView, TypeLibrary


def get_library_path() -> Optional[str]:
    library_path = bn.TextLineField(
        "Path to load type library:", "~/Desktop/libcapstone.bntl"
    )
    bn.get_form_input([library_path], "Apply Type Library Options")
    res_path = os.path.expanduser(library_path.result)
    if os.path.exists(res_path):
        return res_path
    return None


def apply_library(bv: BinaryView, typelib_handle: TypeLibrary):
    exported_objs = typelib_handle.named_objects
    for qualified_name, exported_type in exported_objs.items():
        for func in bv.functions:
            if func.name == qualified_name:
                bn.log_debug(f"Found func: {qualified_name}")
                func.set_user_type(exported_type)


def load_library(bv: BinaryView):
    lib_path = get_library_path()
    if lib_path is None:
        bn.log_error("Supplied path was invalid")
        return
    bn.log_debug(f"lib_path: {lib_path}")
    typelib_handle = TypeLibrary.load_from_file(lib_path)
    bv.add_type_library(typelib_handle)
    apply_library(bv, typelib_handle)
    bv.update_analysis()
