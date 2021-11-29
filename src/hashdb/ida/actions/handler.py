# IDAPython
import ida_kernwin


class Handler(ida_kernwin.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """
    def __init__(self, callback):
        ida_kernwin.action_handler_t.__init__(self)
        self.callback = callback

    def activate(self, context):
        """
        Execute the embedded callback when this context menu is invoked.
        @param context: action_activation_ctx_t
        """
        self.callback(context)
        return 1

    def update(self, context):
        """
        Ensure the context menu is always available in IDA.
        @param context: action_activation_ctx_t
        """
        return ida_kernwin.AST_ENABLE_ALWAYS
