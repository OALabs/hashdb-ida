# IDAPython
import ida_hexrays


# https://hex-rays.com/products/ida/support/idapython_docs/ida_hexrays.html#ida_hexrays.Hexrays_Hooks
class HexRaysHooks(ida_hexrays.Hexrays_Hooks):
    """Extends the Hexrays_Hooks proxy class."""
    def populating_popup(self, widget, popup_handle, vu):
        pass
