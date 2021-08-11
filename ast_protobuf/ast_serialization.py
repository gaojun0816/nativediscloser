import claripy
from angr.state_plugins.sim_action_object import SimActionObject
import ast_protobuf.ast_pb2 as ast_pb2
# import ast_pb2

from pdb import pm

def isOperatorName(name):
    # if name in ["BV", "String", "FP", "Bool", "VS"]:
    if "_" not in name:
        return False
    return True

def convertAst(ast):
    proto_ast = _convertAst(ast)
    if isinstance(ast, SimActionObject):
        ast = ast.ast
    t = type(ast).__name__
    op = type(proto_ast).__name__
    base = ast_pb2.Base()
    if t.startswith("BV"):
        if t == "BV":
            base.node_Bits.node_BV.MergeFrom(proto_ast)
        else:
            string = ast_pb2.BV()
            for attr in string.__dir__():
                if attr.endswith(op):
                    tmp = getattr(base.node_Bits.node_BV, attr)
                    tmp.MergeFrom(proto_ast)
    elif t.startswith("FP"):
        if t == "FP":
            base.node_Bits.node_FP.MergeFrom(proto_ast)
        else:
            string = ast_pb2.FP()
            for attr in string.__dir__():
                if attr.endswith(op):
                    tmp = getattr(base.node_Bits.node_FP, attr)
                    tmp.MergeFrom(proto_ast)
    elif t.startswith("String"):
        if t == "String":
            base.node_Bits.node_String.MergeFrom(proto_ast)
        else:
            string = ast_pb2.String()
            for attr in string.__dir__():
                if attr.endswith(op):
                    tmp = getattr(base.node_Bits.node_String, attr)
                    tmp.MergeFrom(proto_ast)
    elif t.startswith("Bool"):
        # if t == "Bool":
        #     base.node_Bits.node_Bool.MergeFrom(proto_ast)
        # else:
        string = ast_pb2.Bool()
        for attr in string.__dir__():
            if attr.endswith(op):
                tmp = getattr(base.node_Bool, attr)
                tmp.MergeFrom(proto_ast)
    elif t.startswith("Int"):
        if t == "Int":
            base.node_Bits.node_Int.MergeFrom(proto_ast)
        else:
            string = ast_pb2.Int()
            for attr in string.__dir__():
                if attr.endswith(op):
                    tmp = getattr(base.node_Int, attr)
                    tmp.MergeFrom(proto_ast)
    return base

def _convertAst(ast):
    if isinstance(ast, claripy.ast.Base):

        if type(ast).__name__ + "_" + ast.op in ast_pb2.__dict__: # op node

            node = None

            # If type is bool (ie comparison operators) the operators is stored in the argument type node
            if type(ast).__name__ == "Bool" and len(ast.args) > 0 \
               and type(ast.args[0]).__name__ + "_" + ast.op in ast_pb2.__dict__:
                NodeCls = getattr(ast_pb2, type(ast.args[0]).__name__ + "_" + ast.op)
                node = NodeCls()

            else:
                NodeCls = getattr(ast_pb2, type(ast).__name__ + "_" + ast.op)
                node = NodeCls()

            i = 1
            for arg in ast.args:
                argValue = _convertAst(arg)
                if not isinstance(arg, claripy.ast.Base):
                    setattr(node, "arg%i"%i, argValue)
                else:
                    arg_typename = argValue.__class__.__name__
                    if isOperatorName(arg_typename): # If operator
                        SupArgCls = getattr(ast_pb2, arg_typename.split("_")[0])
                        supArgNode = SupArgCls()
                        subSupArgNode = getattr(supArgNode, "op_"+arg_typename)
                        subSupArgNode.CopyFrom(argValue)
                        
                        subNode = getattr(node, "arg%i"%i)
                        subNode.CopyFrom(supArgNode)
                    else: # If BV, FP, String, VS
                        subNode = getattr(node, "arg%i"%i)
                        subNode.CopyFrom(argValue)

                i += 1

            return node
        else:
            # lief node
            if ast.op.endswith("S") or ast.op.endswith("V"):
                NodeCls = getattr(ast_pb2, ast.op)
                node = NodeCls()

                if ast.op.endswith("S"):
                    node.symbol = ast.args[0]
                else:
                    node.value = ast.args[0]

                SupNodeCls = getattr(ast_pb2, ast.op[:-1])
                supNode = SupNodeCls()
                subSupNode = getattr(supNode, "node_"+ast.op)
                subSupNode.CopyFrom(node)
                
                return supNode

            # "oneof" node
            else:
                raise ValueError("oneof node should not be instancied. If not, this case is not implemented")
    elif isinstance(ast, SimActionObject):
        return _convertAst(ast.ast)
    else:
        return ast

if __name__ == "__main__":
    s = claripy.IntToStr((claripy.BVS("x", 64) * (claripy.BVV(9, 64) + claripy.BVS("x", 64)))[32:0]) + (claripy.StringV("toto") + claripy.StringS("toto", 32))

    b = convertAst(s)

    print(str(b))

    print(b.IsInitialized())

    # Parsing and Serialization
    # Finally, each protocol buffer class has methods for writing and reading messages of your chosen type using the protocol buffer binary format. These include:
    #     SerializeToString(): serializes the message and returns it as a string. Note that the bytes are binary, not text; we only use the str type as a convenient container.
    #     ParseFromString(data): parses a message from the given string.

