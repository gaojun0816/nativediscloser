
class Invokee:
    def __init__(self, cls, method_name, signature):
        self.cls = cls
        self.method_name = method_name
        self.signature = signature
        self._static = None

    def __str__(self):
        return f'{self.cls}, {self.method_name}, {self.signature}, {self._static}'


class Record:
    # global records, indexed by the address of corresponding JNI function pointer
    RECORDS = dict()

    def __init__(self, cls, method_name, signature, func_ptr, symbol_name, static_export=False):
        self.cls = cls
        self.method_name = method_name
        self.signature = signature
        self.func_ptr = func_ptr
        self.symbol_name = symbol_name
        self.static_export = static_export
        self._invokees = None # list of method invoked by current native method
        Record.RECORDS.update({func_ptr: self}) # add itself to global record

    def add_invokee(self, *param):
        """Add the Java invokee method information
        The invokee is a Java method invoked by current native function.

        Args:
        *param: should be either an instance of class Invokee or 3 strings
                describing invokee's class name, method name and the signature
                of the method.
        """
        invokee = None
        if len(param) == 1:
            invokee, = param
            if not isinstance(invokee, Invokee):
                raise TypeError('Invokee of Record should be an instance of class Invokee')
        elif len(param) == 3:
            invokee = Invokee(*param)
        else:
            raise TypeError('Parameters should have length of 1 or 3')
        if self._invokees is None:
            self._invokees = list()
        self._invokees.append(invokee)

    def is_invoker(self):
        return self._invokees is not None

    def get_num_invokees(self):
        num = 0
        if self._invokees is not None:
            num = len(self._invokees)
        return num

    def __str__(self):
        result = ''
        invoker = f'{self.cls}, {self.method_name}, {self.signature}, {self.symbol_name}, {self.static_export}'
        if self._invokees is None:
            result = invoker
        else:
            for invokee in self._invokees:
                result += invoker + ', ' + str(invokee) + '\n'
        return result.strip()


