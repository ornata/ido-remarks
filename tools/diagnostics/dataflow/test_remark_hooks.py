"""Execute hooks against synthetic guest memory: decisions, ABI and transparency."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from patch_ido_remarks import instrument, instrument_scheduler, instrument_ugen, HOOK_FUNCTIONS, SCHEDULER_FUNCTIONS, UGEN_FUNCTIONS, XBB_FUNCTIONS, SCHEDULER_HOOK_PATH, DEFINITION_FUNCTIONS

PREFIX = r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define MEM_U32(a) (*(uint32_t *)(mem + (a)))
#define MEM_S32(a) (*(int32_t *)(mem + (a)))
#define MEM_U16(a) (*(uint16_t *)(mem + ((a) ^ 2)))
#define MEM_U8(a) (*(uint8_t *)(mem + ((a) ^ 3)))
#define MEM_S8(a) (*(int8_t *)(mem + ((a) ^ 3)))
'''


@unittest.skipUnless(shutil.which("cc"), "Native C compiler unavailable")
class RemarkHooks(unittest.TestCase):
    def test_ready_source_line_tie_break_is_read_only(self):
        source="\n".join(f"static uint32_t {name}({params}) {{ return 0; }}" for name,_,params in SCHEDULER_FUNCTIONS)
        source=instrument_scheduler(source)+r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    uint32_t ptr=0x10030000,candidate=0x10026390,incumbent=candidate+56;
    for (unsigned i=0;i<7;i++) MEM_U8(ptr+i)="target"[i];
    MEM_U32(0x10030814)=ptr; ido_scheduler_active=0x10027000;
    MEM_U32(candidate+48)=9; MEM_U32(incumbent+48)=7;
    uint8_t before[112]; memcpy(before,mem+candidate,sizeof before);
    errno=EDOM;
    ido_ready_comparison(mem,candidate,incumbent,4,4,0,0,0,0);
    if (errno!=EDOM || memcmp(before,mem+candidate,sizeof before)) return 2;
    free(mem); return 0;
}
'''
        for mode,function,log in self.run_modes(source):
            if mode=="off" or function=="other": self.assertEqual(log,"")
            elif mode=="json":
                event=json.loads(log)
                self.assertEqual(event["deciding_key"],"source_line")
                self.assertFalse(event["candidate_preferred"])

    def test_definition_and_creation_observations(self):
        source="\n".join(f"static void f_{name}({params}) {{ }}" for name,params in HOOK_FUNCTIONS)
        source+="\nstatic uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) { return 0; }"
        source+="\nstatic uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) { return a0; }"
        for name,params,result in DEFINITION_FUNCTIONS:
            body="MEM_U32(0x10028004)=0x10026100; errno=EDOM;" if name=="formlivbb" else "errno=EDOM; return 17;" if result=="uint32_t" else "errno=EDOM;"
            source+=f"\nstatic {result} f_{name}({params}) {{ {body} }}"
        source=instrument(source,definitions=True)+r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    for (unsigned i=0;i<6;i++) MEM_U8(0x1001c4d0+i)="target"[i];
    MEM_U32(0x1001c8d0)=6;
    f_oneproc(mem,0x10010000);
    MEM_U8(0x10011ff0)=81; MEM_U16(0x10011ff2)=3; MEM_U32(0x10011ff4)=42;
    f_readnxtinst(mem,0x10010000);
    MEM_U8(0x10011ff0)=123; MEM_U8(0x10011ff1)=110; MEM_U32(0x10011ff4)=31;
    MEM_U32(0x10011ff8)=4; MEM_S32(0x10011ffc)=-4;
    f_readnxtinst(mem,0x10010000);
    MEM_U32(0x1001cc30)=0x10028000; MEM_U32(0x1001cb38)=1;
    uint32_t chain=0x10026000,block=0x10027000;
    MEM_U8(chain)=3; MEM_U8(chain+1)=14; MEM_U16(block+8)=7;
    f_formlivbb(mem,0x10010000,chain,block,0x10029000);
    if (errno!=EDOM || MEM_U32(0x10028004)!=0x10026100) return 2;
    if (f_newbit(mem,0x10010000,chain,0)!=17 || errno!=EDOM) return 3;
    free(mem); return 0;
}
'''
        for mode,function,log in self.run_modes(source):
            if mode=="off" or function=="other": self.assertEqual(log,"")
            elif mode=="json":
                events=[json.loads(line) for line in log.splitlines()]
                self.assertEqual([e["name"] for e in events],["DefinitionInput","RangeCreated","BitAllocated"])
                self.assertEqual(events[0]["source_line"],42)
                self.assertEqual(events[0]["storage_offset"],-4)
                self.assertEqual(events[-1]["bit"],17)

    def test_scheduler_pool_slot_component_is_read_only(self):
        source="\n".join(f"static uint32_t {name}({params}) {{ return 0; }}" for name,_,params in SCHEDULER_FUNCTIONS)
        source=instrument_scheduler(source)+r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    uint32_t ptr=0x10030000,candidate=0x10026390,incumbent=candidate+56;
    for (unsigned i=0;i<7;i++) MEM_U8(ptr+i)="target"[i];
    MEM_U32(0x10030814)=ptr; ido_scheduler_active=0x10027000;
    uint8_t before[112]; memcpy(before,mem+candidate,sizeof before);
    errno=EDOM;
    ido_scheduler_score(mem,candidate,incumbent,100,101);
    if (errno!=EDOM || memcmp(before,mem+candidate,sizeof before)) return 2;
    free(mem); return 0;
}
'''
        for mode,function,log in self.run_modes(source):
            if mode=="off" or function=="other": self.assertEqual(log,"")
            elif mode=="json":
                event=json.loads(log)
                self.assertTrue(event["slot_decides"])
                self.assertEqual(event["candidate_without_slot"],100)
                self.assertEqual(event["incumbent_without_slot"],100)

    def test_xbb_proposal_observer_preserves_abi_and_guest_memory(self):
        source = "\n".join(f"static uint32_t {name}({params}) {{ return 0; }}" for name, _, params in SCHEDULER_FUNCTIONS)
        source = instrument_scheduler(source)
        for _, original, params, result in XBB_FUNCTIONS:
            body="errno=EDOM; return 3;" if result=="uint32_t" else "errno=EDOM;"
            source += f"\nstatic {result} ido_original_{original}({params}) {{ {body} }}"
        source += "\nstatic void ido_original_xbb(uint8_t *mem,uint32_t sp,uint32_t a0,uint32_t a1) {}"
        source += "\nstatic int wrapper_fflush(uint8_t *mem,uint32_t ptr) { return 0; }\n"
        source += SCHEDULER_HOOK_PATH.with_name("ido_xbb_hooks.c").read_text()
        source += r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    setenv("IDO_XBB_CAPTURE","1",1); setenv("IDO_XBB_FUNCTION","target",1);
    uint32_t ptr=0x10030000,source=0x10026000,target=0x10026100;
    for (unsigned i=0;i<7;i++) MEM_U8(ptr+i)="target"[i];
    MEM_U32(0x10030814)=ptr; MEM_U32(source+64)=8; MEM_U32(target+64)=7;
    MEM_U32(source+68)=0x2000; MEM_U16(target+78)=1; ido_xbb_depth=1;
    uint8_t before[0x200]; memcpy(before,mem+source,sizeof before);
    if (func_42a028(mem,0x10010000,source,target,0,0)!=3 || errno!=EDOM || memcmp(before,mem+source,sizeof before)) return 2;
    free(mem); return 0;
}
'''
        for _, _, log in self.run_modes(source):
            event=json.loads(log)
            self.assertTrue(event["accepted"])
            self.assertEqual((event["source_block"],event["target_block"]),(8,7))

    def test_origin_and_seed_are_read_only(self):
        source = "\n".join(f"static void f_{name}({params}) {{ }}" for name, params in HOOK_FUNCTIONS)
        source += "\nstatic uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) { return 0; }"
        source += "\nstatic uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) { return a0; }"
        source = instrument(source) + r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    for (unsigned i=0;i<6;i++) MEM_U8(0x1001c4d0+i)="target"[i];
    MEM_U32(0x1001c8d0)=6;
    uint32_t owner=0x10026000, target=0x10026100, unit=0x10026200, block=0x10027000;
    MEM_U32(owner+4)=7; MEM_U32(target+4)=8; MEM_U8(owner+32)=1;
    MEM_U32(unit)=block; MEM_U16(block+8)=4; MEM_U8(unit+20)=1;
    uint8_t before[0x1100]; memcpy(before,mem+owner,sizeof before);
    errno=EDOM;
    ido_interference_origin(mem,owner,target,0,0,0x40000000,0);
    ido_seed_selected(mem,owner,target,unit);
    if (errno!=EDOM || memcmp(before,mem+owner,sizeof before)) return 2;
    free(mem); return 0;
}
'''
        for mode, function, log in self.run_modes(source):
            if mode == "off" or function == "other":
                self.assertEqual(log, "")
            elif mode == "json":
                records = [json.loads(line) for line in log.splitlines()]
                self.assertEqual(records[0]["cause"], "colored_interferer")
                self.assertEqual(records[0]["owner_range"], 7)
                self.assertTrue(records[1]["seed_is_definition"])

    def test_conversion_observer_preserves_abi_and_width(self):
        source = "\n".join(f"static void f_{name}({params}) {{ }}" for name, params in HOOK_FUNCTIONS)
        source += "\nstatic uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) { return 0; }"
        source += "\nstatic uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) { errno=EDOM; return a0; }"
        source = instrument(source) + r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    for (unsigned i=0;i<6;i++) MEM_U8(0x1001c4d0+i)="target"[i];
    MEM_U32(0x1001c8d0)=6;
    uint32_t expr=0x10026000, block=0x10027000;
    MEM_U8(expr)=3; MEM_U8(expr+1)=4; MEM_U8(expr+32)=1; MEM_U16(block+8)=7;
    if (func_415f9c(mem,0x10010000,block,expr,8,4)!=expr || errno!=EDOM) return 2;
    free(mem); return 0;
}
'''
        for mode, function, log in self.run_modes(source):
            if mode == "off" or function == "other":
                self.assertEqual(log, "")
            elif mode == "json":
                event = json.loads(log)
                self.assertTrue(event["same_operand"])
                self.assertEqual(event["operand_width_bits"], 8)
                self.assertEqual(event["block"], 7)

    def test_ugen_preserves_return_and_reports_real_reference_count(self):
        source = "\n".join(f"static {result} f_{name}({params});" for name, params, result in UGEN_FUNCTIONS)
        for name, params, result in UGEN_FUNCTIONS:
            body = "errno=EDOM;" if result == "void" else (
                "f_translate(mem,sp,a0); errno=EDOM; return a0;" if name == "translate_tree" else "MEM_U8(a0+25)=7; errno=EDOM; return a0;")
            source += f"\nstatic {result} f_{name}({params}) {{ {body} }}"
        source = instrument_ugen(source) + r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    setenv("IDO_UGEN_SYMBOL","31",1);
    uint32_t node=0x10026000;
    MEM_U8(node+32)=33; MEM_U32(node+36)=31; MEM_U16(node+20)=2;
    MEM_U32(node+16)=256*7;
    if (f_translate_tree(mem,0x10010000,node)!=node || errno!=EDOM || MEM_U8(node+25)!=7) return 2;
    free(mem); return 0;
}
'''
        for mode, function, log in self.run_modes(source):
            if mode != "json":
                self.assertEqual(log, "")
            else:
                events = [json.loads(s) for s in log.splitlines()]
                self.assertEqual(events[2]["register"], 3)
                self.assertEqual(events[2]["reference_count"], 2)
                self.assertEqual(events[2]["node_id"], 7)
                self.assertEqual(events[0]["function"], function)

    def test_split_decision_and_forbidden_contributor(self):
        source = "\n".join(f"static void f_{name}({params}) {{ " + (
            "MEM_U32(a2+40) |= 0x40000000; errno=EDOM;" if name == "updateforbidden" else "") + " }"
            for name, params in HOOK_FUNCTIONS)
        source += "\nstatic uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) { return 0; }"
        source += "\nstatic uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) { return a0; }"
        source = instrument(source) + r'''
int main(void) {
    uint8_t *mem=calloc(1,0x10040000);
    if (!mem) return 1;
    for (unsigned i=0;i<6;i++) MEM_U8(0x1001c4d0+i)="target"[i];
    MEM_U32(0x1001c8d0)=6;
    uint32_t parent=0x10026000, piece=0x10026100, block=0x10027000;
    MEM_U32(parent+4)=1; MEM_U32(piece+4)=2; MEM_U16(block+8)=15;
    MEM_U8(piece+33)=11; MEM_U32(piece+36)=13; MEM_U8(0x1001eb10)=1;
    errno=EDOM;
    ido_adjacency(mem,parent,piece,block,10,11);
    if (errno!=EDOM || MEM_U8(piece+33)!=11) return 2;
    f_updateforbidden(mem,0x10010000,block,0,piece,1);
    if (errno!=EDOM || MEM_U32(piece+40)!=0x40000000) return 3;
    free(mem); return 0;
}
'''
        for mode, function, log in self.run_modes(source):
            if mode == "off" or function == "other":
                self.assertEqual(log, "")
            elif mode == "json":
                records = [json.loads(s) for s in log.splitlines()]
                self.assertFalse(records[0]["accepted"])
                self.assertEqual(records[0]["interferences"] + records[0]["shared"], 23)
                self.assertEqual(records[1]["after"][0], "40000000")

    def run_modes(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.c").write_text(PREFIX + source)
            subprocess.run(["cc", "-std=c11", "-Wno-unused-function", str(root / "test.c"),
                            "-o", str(root / "test")], check=True, capture_output=True)
            for mode, function in (("json", "target"), ("text", "target"), ("off", "target"),
                                   ("json", "other")):
                env = dict(os.environ, IDO_REMARKS=mode, IDO_REMARKS_FUNCTION=function)
                result = subprocess.run([str(root / "test")], env=env, check=True, text=True, capture_output=True)
                yield mode, function, result.stderr

    def test_cse_records_real_reuse_kill_and_bit_transitions(self):
        source = "\n".join(f"static void f_{name}({params}) {{ " + (
            "MEM_U16(a0 + 6)++; errno = EDOM;" if name == "increasecount" else
            "MEM_U32(0x10028000) = 0; errno = EDOM;" if name == "checkexp_ant_av" else "") + " }"
            for name, params in HOOK_FUNCTIONS)
        source += "\nstatic uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) { errno = EDOM; return MEM_U8(a0 + 2); }"
        source += "\nstatic uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) { return a0; }"
        source = instrument(source) + r'''
int main(void) {
    uint8_t *mem = calloc(1, 0x10040000);
    if (!mem) return 1;
    const char *name = "target";
    for (unsigned i=0; i<6; i++) MEM_U8(0x1001c4d0+i)=name[i];
    MEM_U32(0x1001c8d0)=6;
    uint32_t expr=0x10026000, block=0x10027000, chain=0x10026100;
    MEM_U8(expr)=4; MEM_U8(expr+2)=1; MEM_U16(expr+6)=1;
    MEM_U16(expr+8)=17; MEM_U32(expr+12)=3; MEM_U32(expr+16)=block;
    MEM_U8(expr+0x20)=91; MEM_U16(block+8)=42;
    MEM_U16(chain+2)=0; MEM_U16(chain+4)=17; MEM_U16(chain+6)=3;
    MEM_U32(block+0x108)=0x10028000; MEM_U32(block+0x118)=0x10028004;
    MEM_U32(0x10028000)=0x80000000; MEM_U32(0x10028004)=0x80000000;
    f_increasecount(mem, 0x10010000, expr);
    if (MEM_U16(expr+6)!=2 || errno!=EDOM) return 2;
    if (f_treekilled(mem, 0x10010000, expr)!=1 || errno!=EDOM) return 3;
    f_checkexp_ant_av(mem, 0x10010000, chain, block);
    if (MEM_U32(0x10028000)!=0 || MEM_U32(0x10028004)!=0x80000000 || errno!=EDOM) return 4;
    free(mem); return 0;
}
'''
        for mode, function, log in self.run_modes(source):
            if mode == "off" or function == "other":
                self.assertEqual(log, "")
            elif mode == "text":
                self.assertEqual(log.count("[-Rpass-analysis=ido-cse]"), 3)
            else:
                records = [json.loads(s) for s in log.splitlines()]
                self.assertEqual([r["name"] for r in records],
                                 ["LocalReuse", "TreeKilledCheck", "AnticipationAvailability"])
                self.assertEqual(records[0]["count_after"], 2)
                self.assertTrue(records[1]["tree_killed"])
                self.assertTrue(records[2]["anticipated_before"])
                self.assertFalse(records[2]["anticipated_after"])
                self.assertTrue(records[2]["available_after"])

    def test_scheduler_preserves_guest_memory_errno_and_generated_returns(self):
        declarations = "\n".join(f"static uint32_t {name}({params});" for name, _, params in SCHEDULER_FUNCTIONS)
        definitions = []
        for name, original, params in SCHEDULER_FUNCTIONS:
            body = "errno = EDOM; return a0+7;"
            if original == "reorganize_bb":
                body = ("f_start_time(mem, sp, 3, 0x10026000, 0, 0); "
                        "f_start_instruction(mem, sp, 10, 0x8ca20000, 0, 0); "
                        "f_is_node_better(mem, sp, 0x10026000, 0x10026040, 1, 2); "
                        "func_42d698(mem, sp, 13, 0x10026000, 0x10026040, 3, 1); " + body)
            definitions.append(f"static uint32_t {name}({params}) {{ {body} }}")
        source = instrument_scheduler(declarations + "\n" + "\n".join(definitions)) + r'''
int main(void) {
    uint8_t *mem=calloc(1, 0x10040000);
    if (!mem) return 1;
    uint32_t ptr=0x10030000, block=0x10027000, sp=0x10010000;
    const char *name="target";
    for (unsigned i=0; i<7; i++) MEM_U8(ptr+i)=name[i];
    MEM_U32(0x10030814)=ptr; MEM_U32(0x10030810)=8;
    MEM_U16(block+0x3c)=5; MEM_U16(0x1002602e)=8;
    MEM_U32(0x10026000)=0x8ca20000; MEM_U32(0x10026014)=2;
    MEM_U32(sp+16)=5; MEM_U32(sp+20)=6;
    uint8_t before[0x20000]; memcpy(before, mem+0x10010000, sizeof before);
    uint32_t result=f_reorganize_bb(mem, sp, block, 0);
    if (result!=block+7 || errno!=EDOM || memcmp(before, mem+0x10010000, sizeof before)) return 2;
    free(mem); return 0;
}
'''
        for mode, function, log in self.run_modes(source):
            if mode == "off" or function == "other":
                self.assertEqual(log, "")
            elif mode == "text":
                self.assertEqual(log.count("[-Rpass-analysis=ido-scheduler]"), 6)
            else:
                records = [json.loads(s) for s in log.splitlines()]
                self.assertEqual([r["event"] for r in records], list(range(1, 7)))
                timing = next(r for r in records if r["name"] == "StartTime")
                self.assertEqual(timing["dependency_ready_cycle"], 8)
                self.assertEqual(timing["resource_delay"], 2)
                priority = next(r for r in records if r["name"] == "PriorityComparison")
                self.assertEqual(priority["candidate_weight"], 5)
                self.assertEqual(priority["incumbent_weight"], 6)
                self.assertEqual(records[0]["procedure_symbol"], 8)
                self.assertEqual(records[0]["procedure_ordinal"], 1)
