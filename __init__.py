import os

from binaryninja import BinaryView, Function
from binaryninja import CoreSymbol, Logger
from binaryninja import PluginCommand
from binaryninja import SymbolType, SymbolBinding
from binaryninja import TypeLibrary


def create_type_library(log: Logger, bv: BinaryView, func_list: list[Function]) -> TypeLibrary:
    typelib = TypeLibrary.new(bv.arch, os.path.basename(bv.file.filename))
    typelib.add_platform(bv.platform)
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


def export_functions(bv: BinaryView):
    log = bv.create_logger("TypeLib_Exporter")

    func_list = bv.get_symbols_of_type(SymbolType.FunctionSymbol)
    export_func_syms = [sym for sym in func_list
                        if sym.binding == SymbolBinding.GlobalBinding or sym.binding == SymbolBinding.WeakBinding]

    export_funcs = get_funcs_from_syms(log, bv, export_func_syms)
    log.log_debug(f"Discovered {len(export_funcs)} exported functions")

    typelib = create_type_library(log, bv, export_funcs)
    typelib.finalize()
    log.log_info(f"Exported {len(export_funcs)} functions to {os.path.basename(bv.file.filename)}.bntl")
    typelib.write_to_file(f"~/{os.path.basename(bv.file.filename)}.bntl")
    return


def is_valid(bv: BinaryView):
    return bv.has_initial_analysis()


PluginCommand.register("Export As Type Library", "Compiles the exported function types into a type library",
                       export_functions, is_valid)
