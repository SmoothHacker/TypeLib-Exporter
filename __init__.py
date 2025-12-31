from binaryninja import BinaryView, PluginCommand

from . import apply
from . import export


def is_valid(bv: BinaryView):
    return bv.has_initial_analysis()


PluginCommand.register(
    "Export As Type Library",
    "Compiles the exported function types into a type library",
    export.export_functions,
    is_valid,
)
PluginCommand.register(
    "Apply Type Library",
    "Loads and applies a type library to the current binary view",
    apply.load_library,
    is_valid,
)
