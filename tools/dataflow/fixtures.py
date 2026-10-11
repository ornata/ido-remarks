"""Bounded declarative MIPS differential fixtures; no dynamic model code."""
import hashlib
import itertools
from pathlib import Path

ROM_SHA1 = "da1a1e47a86720f9d54fb2d2d247480041bda824"
MASK = 0xffffffff


def integer(value):
    result = int(value, 0) if isinstance(value, str) else value
    if type(result) is not int or not 0 <= result <= MASK:
        raise ValueError("Require a 32-bit unsigned integer or hex string")
    return result


def expand_cases(config):
    cases = list(config.get("cases", []))
    matrix = config.get("matrix")
    if matrix:
        axes = matrix["axes"]
        if not axes or len({a["register"] for a in axes}) != len(axes):
            raise ValueError("Matrix needs distinct register axes")
        count = 1
        for axis in axes:
            count *= len(axis["values"])
        if not 1 <= count <= 4096:
            raise ValueError("Matrix must expand to 1..4096 cases")
        for index, values in enumerate(itertools.product(*(a["values"] for a in axes))):
            case = dict(matrix["base"])
            case["id"] = f'matrix_{index}'
            case["registers"] = {**case.get("registers", {}), **{a["register"]: v for a, v in zip(axes, values)}}
            cases.append(case)
    if not 1 <= len(cases) <= 4096 or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("Require 1..4096 uniquely named cases")
    return cases


def load_program(spec, directory):
    """Require a hash-bound linked ELF or the canonical ROM's explicit code span."""
    if "elf" in spec:
        from mips_semantics import LinkedElf
        path = (directory / spec["elf"]).resolve()
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != spec.get("sha256"):
            raise ValueError("ELF hash mismatch")
        linked = LinkedElf(data)
        entry, size = linked.symbols[spec["function"]]
        if "entry" in spec and entry != integer(spec["entry"]):
            raise ValueError("Function entry differs from manifest")
        code = linked.function(spec["function"], entry)
        provenance = {"path": str(path), "sha256": spec["sha256"], "function": spec["function"],
                      "authority": "hash-bound caller-selected ELF; ROM identity not established"}
        symbols = linked.symbols
    elif "rom" in spec:
        path = (directory / spec["rom"]).resolve()
        data = path.read_bytes()
        if spec.get("sha1") != ROM_SHA1 or hashlib.sha1(data).hexdigest() != ROM_SHA1:
            raise ValueError("Requires canonical US ROM hash")
        entry, size, offset = integer(spec["entry"]), spec["size"], integer(spec["offset"])
        if type(size) is not int or size <= 0:
            raise ValueError("Invalid ROM function size")
        code = data[offset:offset + size]
        if len(code) != size:
            raise ValueError("ROM span is truncated")
        provenance = {"path": str(path), "sha1": ROM_SHA1, "offset": offset,
                      "authority": "canonical ROM bytes; span/ABI supplied by analyst"}
        symbols = {}
    else:
        raise ValueError("Program needs a linked ELF or canonical ROM")
    if not code or len(code) % 4 or entry % 4:
        raise ValueError("Code must contain aligned complete instructions")
    return {"code": code, "entry": entry, "size": size, "symbols": symbols,
            "provenance": dict(provenance, entry=entry, size=size, code_sha256=hashlib.sha256(code).hexdigest())}


def helper_addresses(config, side, program):
    helpers = {}
    for name, contract in config.get("helpers", {}).items():
        location = contract[side]
        address = program["symbols"][location["symbol"]][0] if "symbol" in location else integer(location["address"])
        if address in helpers:
            raise ValueError("Ambiguous helper entry")
        helpers[address] = (name, contract)
    return helpers


def execute(program, case, config, side):
    from unicorn import Uc, UcError, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn import mips_const as registers
    from mips_semantics import physical
    from dataflow.machine import REGS

    register_ids = {r: getattr(registers, "UC_MIPS_REG_" + ("FP" if r == "s8" else r.upper())) for r in REGS}
    register_ids.update({f"f{i}": getattr(registers, f"UC_MIPS_REG_F{i}") for i in range(32)})
    if hasattr(registers, "UC_MIPS_REG_FCSR"):
        register_ids["fcsr"] = registers.UC_MIPS_REG_FCSR

    def register(name):
        if name not in register_ids:
            raise ValueError("Unsupported fixture register: " + name)
        return register_ids[name]

    entry, code = program["entry"], program["code"]
    physical(entry + len(code) - 1)
    code_low = physical(entry)
    sentinel, stack_low, stack_high = 0x80000300, 0x3fe000, 0x3ff000
    region_specs = case.get("regions", [])
    if not region_specs or len({r["name"] for r in region_specs}) != len(region_specs):
        raise ValueError("Require distinct nonempty fixture memory regions")
    regions = []
    for spec in region_specs:
        data = bytes.fromhex(spec["hex"])
        address = integer(spec["address"])
        if not data or len(data) > 0x100000:
            raise ValueError("Region length must be 1..1048576")
        physical(address + len(data) - 1)
        regions.append({**spec, "low": physical(address), "high": physical(address) + len(data), "data": data})
    spans = [(code_low, code_low + len(code)), (stack_low, stack_high)] + [(r["low"], r["high"]) for r in regions]
    if any(a < d and c < b for i, (a, b) in enumerate(spans) for c, d in spans[i + 1:]):
        raise ValueError("Fixture regions/code/stack overlap; model aliases as one backing region")
    if any(a <= physical(sentinel) < b for a, b in spans):
        raise ValueError("Fixture overlaps return sentinel")
    helpers = helper_addresses(config, side, program)
    for address in helpers:
        p = physical(address)
        if address % 4 or any(a <= p < b for a, b in spans) or p == physical(sentinel):
            raise ValueError("Modeled helper must be a separate aligned entry")
    machine = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)
    pages = {p for a, b in spans for p in range(a & ~0xfff, (b + 0xfff) & ~0xfff, 0x1000)}
    pages.update(physical(a) & ~0xfff for a in [sentinel, *helpers])
    for page in sorted(pages):
        machine.mem_map(page, 0x1000)
    machine.mem_write(code_low, code)
    for region in regions:
        machine.mem_write(region["low"], region["data"])
    for name, value in case.get("registers", {}).items():
        if name in ("zero", "sp", "ra", "pc"):
            raise ValueError("Fixture cannot override reserved registers")
        machine.reg_write(register(name), integer(value))
    preserved = {register(name): machine.reg_read(register(name)) for name in ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]}
    # Distinct initial values make accidental callee-saved corruption observable.
    for index, name in enumerate(["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]):
        if name not in case.get("registers", {}):
            preserved[register(name)] = 0x91700000 + index * 0x10101
            machine.reg_write(register(name), preserved[register(name)])
    for index in range(20, 32):
        name = f"f{index}"
        if name not in case.get("registers", {}):
            machine.reg_write(register(name), 0x3f800000 + index)
        preserved[register(name)] = machine.reg_read(register(name))
    machine.reg_write(register("sp"), 0x80000000 + stack_high - 16)
    preserved[register("sp")] = machine.reg_read(register("sp"))
    machine.reg_write(register("ra"), sentinel)
    traces, helper_trace, counts, errors = {"reads": [], "writes": []}, [], {}, []
    observed = config.get("observe", {})
    helper_models = case.get("helper_results", {})

    def fail(reason):
        errors.append(reason)
        machine.emu_stop()

    def data_region(address, size, writable=False):
        low = address & 0x1fffffff
        matches = [r for r in regions if r["low"] <= low and low + size <= r["high"] and (not writable or r.get("writable", True))]
        return matches[0] if len(matches) == 1 else None

    def memory_hook(uc, access, address, size, value, writable):
        low = address & 0x1fffffff
        if stack_low <= low and low + size <= stack_high:
            return
        region = data_region(address, size, writable)
        if region is None:
            if not writable and code_low <= low and low + size <= code_low + len(code):
                return
            fail(f"Unsupported {'write' if writable else 'read'} at {address:#x}/{size}")
            return
        kind = "writes" if writable else "reads"
        selected = observed.get("write_order" if writable else "read_order", [])
        if region["name"] in selected:
            payload = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "big") if writable else bytes(uc.mem_read(low, size))
            traces[kind].append({"region": region["name"], "offset": low - region["low"], "size": size, "hex": payload.hex()})

    def code_hook(uc, address, size, unused):
        if address in helpers:
            name, contract = helpers[address]
            index = counts.get(name, 0)
            models = helper_models.get(name, [])
            if index >= len(models):
                fail("Unmodeled helper invocation: " + name)
                return
            model = models[index]
            counts[name] = index + 1
            args = {r: uc.reg_read(register(r)) & MASK for r in contract.get("arguments", [])}
            if "expected_arguments" in model and args != {k: integer(v) for k, v in model["expected_arguments"].items()}:
                fail("Helper arguments violate fixture contract: " + name)
                return
            writes = []
            for write in model.get("writes", []):
                destination = integer(write["address"]) if "address" in write else (args[write["argument"]] + write.get("offset", 0)) & MASK
                payload = bytes.fromhex(write["hex"])
                region = data_region(destination, len(payload), True)
                if not payload or region is None:
                    fail("Helper write leaves fixture memory: " + name)
                    return
                uc.mem_write(destination & 0x1fffffff, payload)
                writes.append({"region": region["name"], "offset": (destination & 0x1fffffff) - region["low"], "hex": payload.hex()})
            outputs = {r: integer(v) for r, v in model.get("registers", {}).items()}
            for r, value in outputs.items():
                if r in ("zero", "sp", "ra", "pc"):
                    fail("Helper model overwrites reserved register")
                    return
                uc.reg_write(register(r), value)
            helper_trace.append({"name": name, "arguments": args, "outputs": outputs, "writes": writes})
            uc.reg_write(registers.UC_MIPS_REG_PC, uc.reg_read(register("ra")))
        elif not (entry <= address and address + size <= entry + len(code)):
            fail(f"Control left selected function at {address:#x}")

    machine.hook_add(UC_HOOK_CODE, code_hook)
    machine.hook_add(UC_HOOK_MEM_READ, memory_hook, False)
    machine.hook_add(UC_HOOK_MEM_WRITE, memory_hook, True)
    limits = config.get("limits", {})
    instructions, timeout = limits.get("instructions", 10000), limits.get("timeout_us", 100000)
    if type(instructions) is not int or type(timeout) is not int or not 1 <= instructions <= 1000000 or not 1 <= timeout <= 10000000:
        raise ValueError("Invalid execution budget")
    try:
        machine.emu_start(entry, sentinel, count=instructions, timeout=timeout)
    except UcError as exc:
        raise ValueError("Emulation failed: " + str(exc)) from exc
    if errors:
        raise ValueError(errors[0])
    if machine.reg_read(registers.UC_MIPS_REG_PC) != sentinel:
        raise ValueError("Function did not return within execution budget")
    if any(machine.reg_read(r) != value for r, value in preserved.items()):
        raise ValueError("Callee-saved register or stack ABI violation")
    if any(counts.get(name, 0) != len(models) for name, models in helper_models.items()):
        raise ValueError("Not all declared helper outcomes were consumed")
    known_regions = {r["name"] for r in regions}
    if any(set(observed.get(key, [])) - known_regions for key in ("read_order", "write_order")):
        raise ValueError("Observation names absent region")
    return {"returns": {r: machine.reg_read(register(r)) & MASK for r in observed.get("returns", ["v0"])},
            "memory": {r["name"]: bytes(machine.mem_read(r["low"], len(r["data"]))).hex() for r in regions},
            **traces, "helpers": helper_trace}


def differences(original, candidate):
    return {key: {"original": original[key], "candidate": candidate[key]} for key in original if original[key] != candidate[key]}


def run_suite(programs, config, executor=execute):
    if config.get("schema") != 1 or set(programs) != {"original", "candidate", "negative"}:
        raise ValueError("Require schema 1 and an original, candidate and negative control")
    cases = expand_cases(config)
    results, mismatches, negative_detected, failures = [], 0, 0, 0
    for case in cases:
        observations = {}
        errors = {}
        for side, program in programs.items():
            try:
                observations[side] = executor(program, case, config, side)
            except (ValueError, KeyError) as exc:
                errors[side] = str(exc)
        if errors:
            failures += 1
            results.append({"case": case["id"], "status": "execution_error", "errors": errors})
            continue  # A crashing negative is NOT a detected behavioral difference.
        change = differences(observations["original"], observations["candidate"])
        negative = differences(observations["original"], observations["negative"])
        mismatches += bool(change)
        negative_detected += bool(negative)
        results.append({"case": case["id"], "status": "mismatch" if change else "pass", "candidate_differences": change,
                        "negative_differences": negative, "observations": observations})
    return {"status": "passed" if not failures and not mismatches and negative_detected else "failed",
            "cases_run": len(cases), "candidate_mismatches": mismatches, "execution_failures": failures,
            "negative_control_cases_detected": negative_detected, "cases": results}
