from binaryninja import BinaryView, PluginCommand

from . import export


def is_valid(bv: BinaryView):
    return bv.has_initial_analysis()


PluginCommand.register("Export As Type Library", "Compiles the exported function types into a type library",
                       export.export_functions, is_valid)
