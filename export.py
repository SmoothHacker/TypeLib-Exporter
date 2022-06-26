import os

import binaryninja as bn
from binaryninja import BinaryView
from binaryninja import CoreSymbol, Logger
from binaryninja import SymbolType, SymbolBinding
from binaryninja import TypeLibrary, Function


def create_type_library(log: Logger, bv: BinaryView, func_list: list[Function], config: dict) -> TypeLibrary:
    typelib = TypeLibrary.new(bv.arch, os.path.basename(bv.file.filename))
    typelib.add_platform(bv.platform)

    if "alternate_names" in config:
        name_list = [name.strip() for name in config["alternate_names"].split(";")]
        for name in name_list:
            typelib.add_alternate_name(name)

    if "dependency_name" in config:
        typelib.dependency_name = config["dependency_name"]
    log.log_debug(f"Exporting {len(func_list)} functions to a type library")
    for func in func_list:
        bv.export_object_to_library(typelib, func.name, func.function_type)
    return typelib


def get_funcs_from_syms(log: Logger, bv: BinaryView, func_syms: list[CoreSymbol]) -> list[Function]:
    func_list = []
    for sym in func_syms:
        res = bv.get_function_at(sym.address)
        if res is None:
            log.log_warn(f"Function: {sym.name} at address: {sym.address} does not exist in the current binary view")
        else:
            func_list.append(res)

    return func_list


def get_config_options(bv: BinaryView):
    alternate_names = bn.TextLineField("Alternative Names (optional):", "lib_musl.so;lib_musl.so.5")
    export_path = bn.TextLineField("Path to store type library:", f"{bv.file.filename}.bntl")
    dependency_name = bn.TextLineField("Dependency Name (optional):")
    bn.get_form_input([alternate_names, export_path, dependency_name], "Export as Type Library Options")

    config = {"alternate_names": alternate_names.result, "export_path": export_path.result,
              "dependency_name": dependency_name.result}
    return config


def export_functions(bv: BinaryView):
    log = bv.create_logger("TypeLib_Exporter")
    config = get_config_options(bv)
    if not os.path.exists(os.path.dirname(os.path.expanduser(config['export_path']))):
        log.log_error(f"Please specify a path to export the type library: {config['export_path']}")
        return

    func_list = bv.get_symbols_of_type(SymbolType.FunctionSymbol)
    export_func_syms = [sym for sym in func_list
                        if sym.binding == SymbolBinding.GlobalBinding or sym.binding == SymbolBinding.WeakBinding]

    export_funcs = get_funcs_from_syms(log, bv, export_func_syms)
    log.log_debug(f"Discovered {len(export_funcs)} exported functions")

    typelib = create_type_library(log, bv, export_funcs, config)
    typelib.finalize()
    log.log_info(f"Exported {len(export_funcs)} functions to {config['export_path']}")
    typelib.write_to_file(config['export_path'])
