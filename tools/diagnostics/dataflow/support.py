"""Authored test records; independent of game binaries."""

from dataflow.machine import Instruction


def ins(address, opcode, *operands, word=0):
    return Instruction(address, word, opcode, operands)


def leaf(body):
    end = body[-1].address + 4
    return body + [ins(end, "jr", "ra"), ins(end + 4, "sll", "zero", "zero", "0")]


def constant(value, size=4):
    return {
        "schema": 2,
        "analysis": "backward_value_dependencies",
        "root": {"node": 0},
        "nodes": [
            {
                "id": 0,
                "frontier": "constant",
                "varnode": {"space": "const", "offset": f"{value:x}", "size": size},
            }
        ],
    }
