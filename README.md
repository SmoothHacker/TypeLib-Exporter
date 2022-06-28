# BN TypeLib Exporter

This plugin compiles exported functions and its corresponding types into a Binary Ninja type library. It can also load
and apply
a type library from disk. 2 buttons in the plugin dropdown menu are created, `Export As Type Library`
and `Apply Type Library`.
For type library exporting, a pop-up window will show detailing what options you would like to specify. Options include
alternative names(libcurl.so.5.0.0, libcurl.so.5, libcurl.so), a dependency name, and the path where you want the
library exported to.
For type library importing, a pop-up window will ask for the path to a `.bntl` file which will be imported and applied
to the
current binary view and any successive binary view in the current session.

A potential workflow for this plugin would be to compile an open source library with debug information, load it into
Binary Ninja,
run the debug info parser, and export it to a type library.

## Future Plans
- [ ] Headless support
