# IDAPython
import ida_kernwin


# https://hex-rays.com/products/ida/support/idapython_docs/ida_kernwin.html#ida_kernwin.UI_Hooks
class UiHooks(ida_kernwin.UI_Hooks):
    """
    Extends the UI_Hooks proxy class.
    """
