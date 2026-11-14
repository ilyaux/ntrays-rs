"""Build/decompile the legacy FRED/MSR/TLB forms without executing fixture code or opening a GUI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

CASES = {
    'erets_case': 'db 0f2h,0fh,1,0cah',
    'eretu_case': 'db 0f3h,0fh,1,0cah',
    'fred_frame': 'sub rsp,40h\n mov qword ptr [rsp],1234h\n db 0f2h,0fh,1,0cah',
    'wrmsrns_case': 'mov rax,1122334455667788h\n mov rdx,99aabbccddeeff00h\n mov rcx,12345678c0000101h\n db 0fh,1,0c6h',
    'wrmsrns_flags': 'xor eax,eax\n mov ecx,0c0000101h\n mov eax,1\n mov edx,2\n db 0fh,1,0c6h\n setz al\n movzx eax,al',
    'invlpgb_case': 'mov rax,1234567007h\n mov ecx,80000002h\n mov edx,120000h\n db 0fh,1,0feh',
    'invlpgb32_case': 'mov rax,1234567007h\n mov ecx,80000002h\n mov edx,120000h\n db 67h,0fh,1,0feh',
    'invlpgb_flags': 'xor eax,eax\n mov rax,1234567007h\n mov ecx,0\n mov edx,0\n db 0fh,1,0feh\n setz al\n movzx eax,al',
    'broadcast_pair': 'mov rax,rcx\n mov ecx,2\n mov edx,0\n db 0fh,1,0feh\n db 0fh,1,0ffh',
    'tlbsync_case': 'db 0fh,1,0ffh\n mov eax,1234h',
    'tlbsync_flags': 'xor eax,eax\n db 0fh,1,0ffh\n setc al\n movzx eax,al',
    'lkgs_ax': 'mov rax,1122334400000010h\n db 0f2h,0fh,0,0f0h',
    'lkgs_r8': 'mov r8,1122334400000010h\n db 0f2h,41h,0fh,0,0f0h\n mov rax,r8',
    'lkgs_rexw': 'mov rax,1122334400000010h\n db 0f2h,48h,0fh,0,0f0h',
    'lkgs_flags': 'xor eax,eax\n mov eax,10h\n db 0f2h,0fh,0,0f0h\n setz al\n movzx eax,al',
    'lkgs_mem': 'mov rax,rcx\n db 0f2h,0fh,0,30h\n mov rax,rcx',
    'lkgs_disp': 'db 0f2h,0fh,0,71h,0fch\n mov rax,rcx',
    'lkgs_sib': 'mov r8,rcx\n mov r9,rdx\n db 0f2h,43h,0fh,0,74h,88h,0f0h\n mov rax,r8',
    'lkgs_addr32': 'mov rax,rcx\n db 67h,0f2h,0fh,0,30h\n mov rax,rcx',
    'lkgs_gs': 'db 65h,0f2h,0fh,0,31h\n mov rax,rcx',
    'lkgs_stack': 'sub rsp,28h\n mov word ptr [rsp+20h],10h\n db 0f2h,0fh,0,74h,24h,20h\n add rsp,28h\n mov eax,10h',
    'lkgs_rip': 'db 0f2h,0fh,0,35h\n dd 1\n ret\n dw 10h',
    'clac_control': 'db 0fh,1,0cah\n mov eax,1234h',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def worker(cfg):
    sys.path.insert(0, str(Path(cfg['ida'])/'idalib/python'))
    import idapro
    import ida_auto, ida_bytes, ida_funcs, ida_hexrays as hx, ida_ida, ida_idaapi, ida_idp, ida_loader, ida_name, ida_segment, ida_typeinf as ti, ida_ua, idautils
    assert idapro.open_database(cfg['binary'], False) == 0
    try:
        ida_ida.inf_set_kernel_mode(True)
        assert hx.init_hexrays_plugin() or (ida_loader.load_plugin('hexx64') and hx.init_hexrays_plugin())
        plugin = ida_loader.load_plugin(cfg['plugin']); assert plugin
        ida_auto.auto_wait()
        addresses = {name: ida_name.get_name_ea(ida_idaapi.BADADDR,name) for name in CASES}
        for name,ea in addresses.items():
            assert ea != ida_idaapi.BADADDR,name
            t=ti.tinfo_t(); decl=f'void __noreturn {name}(void);' if name.startswith('ere') or name=='fred_frame' else f'unsigned __int64 {name}(unsigned __int64 a, unsigned __int64 b);'
            assert ti.parse_decl(t,None,decl,ti.PT_SIL) and ti.apply_tinfo(ea,t,ti.TINFO_DEFINITE),name
        ida_auto.auto_wait(); hx.clear_cached_cfuncs()

        # Compare LKGS address operands against the native MOV r16,r/m16 decoder.
        matrix = {
            'rax': ('f20f0030','668b30'), 'r13': ('f2410f007500','66418b7500'),
            'rsp': ('f20f003424','668b3424'), 'disp8': ('f20f0070f0','668b70f0'),
            'disp32': ('f20f00b078563412','668bb078563412'),
            'sib': ('f2430f007488f0','66438b7488f0'),
            'no_base_index': ('f2420f00348d78563412','66428b348d78563412'),
            'absolute64': ('f20f00342500ffffff','668b342500ffffff'),
            'absolute32': ('67f20f00342500ffffff','67668b342500ffffff'),
            'rip': ('f20f003578563412','668b3578563412'),
            'eip': ('67f20f003578563412','67668b3578563412'), 'gs': ('65f20f0030','65668b30'),
        }
        scratch=0x200000000
        assert ida_segment.add_segm(0,scratch,scratch+0x1000,'DecoderMatrix','CODE')
        segment=ida_segment.getseg(scratch);segment.bitness=2;ida_segment.update_segm(segment)
        matrix_rows=[]
        for index,(name,(raw,reference)) in enumerate(matrix.items()):
            ea=scratch+index*64;ref_ea=ea+32
            ida_bytes.put_bytes(ea,bytes.fromhex(raw));ida_bytes.put_bytes(ref_ea,bytes.fromhex(reference))
            ins=ida_ua.insn_t();ref=ida_ua.insn_t()
            assert ida_ua.decode_insn(ins,ea)==len(bytes.fromhex(raw)),name
            assert ida_ua.decode_insn(ref,ref_ea)==len(bytes.fromhex(reference)),name
            a,b=ins.ops[0],ref.ops[1]
            for field in ('type','reg','dtype','specflag1','specflag2','specval'):
                assert getattr(a,field)==getattr(b,field),(name,field,getattr(a,field),getattr(b,field))
            if name in ('rip','eip'):
                mask=(1<<(32 if name=='eip' else 64))-1
                assert (a.addr-ea-ins.size)&mask==(b.addr-ref_ea-ref.size)&mask,name
            else:assert a.addr==b.addr,name
            # Compare address mode; short/large displacement display flags need not be identical.
            assert ins.auxpref & 0x1018 == ref.auxpref & 0x1018,(name,ins.auxpref,ref.auxpref)
            if a.offb:assert a.offb==b.offb+1,name
            matrix_rows.append({'name':name,'size':ins.size,'address':a.addr})
        edge=scratch+0x1000-4
        ida_bytes.put_bytes(edge,bytes.fromhex('f20f01ca'))
        ins=ida_ua.insn_t();assert ida_ua.decode_insn(ins,edge)==4,'instruction at segment boundary'

        def capture(name, cached=False):
            ea=addresses[name]; hf=hx.hexrays_failure_t();cf=hx.decompile(ea,hf,0 if cached else hx.DECOMP_NO_CACHE)
            assert cf,f'{name}: {hf.desc()}'
            class Calls(hx.ctree_visitor_t):
                def __init__(self):super().__init__(hx.CV_FAST);self.calls=[];self.returns=[]
                def visit_expr(self,e):
                    if e.op==hx.cot_call and e.x.op==hx.cot_helper:
                        self.calls.append({'name':e.x.helper,'formal_sizes':[a.formal_type.get_size() for a in e.a],
                            'noreturn':bool(e.a.flags & hx.CFL_NORET),'args':[{'size':a.type.get_size(),
                            'value':a.n._value & ((1<<(a.type.get_size()*8))-1) if a.op==hx.cot_num else None} for a in e.a]})
                    return 0
                def visit_insn(self,i):
                    if i.op==hx.cit_return and i.creturn.expr.op==hx.cot_num:self.returns.append(i.creturn.expr.n._value)
                    return 0
            visitor=Calls();visitor.apply_to(cf.body,None)
            text=str(cf); rows=[]
            for address in idautils.FuncItems(ea):
                insn=ida_ua.insn_t(); size=ida_ua.decode_insn(insn,address)
                assert size
                rows.append({'ea':address,'size':size,'itype':insn.itype,'mnem':ida_ua.print_insn_mnem(address),
                    'bytes':ida_bytes.get_bytes(address,size).hex(),'return':ida_idp.is_ret_insn(insn),
                    'ops':[{'type':o.type,'dtype':o.dtype,'reg':o.reg,'addr':o.addr} for o in list(insn.ops)[:1]]})
            return {'text':text,'instructions':rows,'calls':visitor.calls,'returns':visitor.returns}

        rows={name:capture(name) for name in CASES}
        Path(cfg['result']).with_name('observed.json').write_text(json.dumps(rows,indent=2))
        for name,helper in [('erets_case','__erets'),('eretu_case','__eretu'),('fred_frame','__erets'),
            ('wrmsrns_case','__wrmsrns'),('wrmsrns_flags','__wrmsrns'),('invlpgb_case','__invlpgb'),
            ('invlpgb32_case','__invlpgb'),('broadcast_pair','__tlbsync'),('tlbsync_case','__tlbsync'),('tlbsync_flags','__tlbsync')]:
            assert helper+'(' in rows[name]['text'],(name,rows[name]['text'])
            assert '__asm' not in rows[name]['text'],name
        for name in CASES:
            if name.startswith('lkgs_'):
                assert '__lkgs(' in rows[name]['text'] and '__asm' not in rows[name]['text'],(name,rows[name]['text'])
        assert '__clac(' in rows['clac_control']['text'] and '__erets' not in rows['clac_control']['text']
        for name in ('erets_case','eretu_case','fred_frame'):
            inst=next(v for v in rows[name]['instructions'] if v['itype']>=0x8000)
            assert inst['return'] and not list(idautils.CodeRefsFrom(inst['ea'],True)),name
        assert '4660' in rows['fred_frame']['text'] or '0x1234' in rows['fred_frame']['text']
        call=lambda name,helper:next(c for c in rows[name]['calls'] if c['name']==helper)['args']
        assert call('wrmsrns_case','__wrmsrns')==[{'size':4,'value':0xc0000101},{'size':8,'value':(0xddeeff00<<32)|0x55667788}]
        assert rows['wrmsrns_case']['returns']==[0x1122334455667788]
        for name,width,desc in [('invlpgb_case',8,0x1234567007),('invlpgb32_case',4,0x34567007)]:
            assert call(name,'__invlpgb')==[{'size':width,'value':desc},{'size':4,'value':0x80000002},{'size':4,'value':0x120000}]
            assert rows[name]['returns']==[0x1234567007]
        for name in ('lkgs_ax','lkgs_r8','lkgs_rexw'):
            assert call(name,'__lkgs')==[{'size':4,'value':16}]
            assert next(c for c in rows[name]['calls'] if c['name']=='__lkgs')['formal_sizes']==[2]
            assert rows[name]['returns']==[0x1122334400000010]
        for name in ('erets_case','eretu_case','fred_frame'):
            assert next(c for c in rows[name]['calls'] if c['name'] in ('__erets','__eretu'))['noreturn']
        for name in ('wrmsrns_flags','invlpgb_flags','lkgs_flags'):assert rows[name]['returns']==[1],name
        assert '__readgsword(' in rows['lkgs_gs']['text']
        assert '(_WORD *)(unsigned int)a' in rows['lkgs_addr32']['text']
        assert rows['broadcast_pair']['text'].index('__invlpgb(') < rows['broadcast_pair']['text'].index('__tlbsync(')
        assert 'return 1;' in rows['wrmsrns_flags']['text'] and 'return 0;' in rows['tlbsync_flags']['text']
        # Exercise the normal decompiler cache, retaining correct disassembly while helpers are off.
        for enabled,mask in ((True,0x3e),(False,0x3f),(True,0x3f)):
            assert ida_loader.run_plugin(plugin,0x4e54525301000000|int(enabled)|(mask<<8)|(1<<16))
            for name in ('erets_case','wrmsrns_case','lkgs_mem'):
                row=capture(name,cached=True)
                assert ('__asm' not in row['text']) == (enabled and mask==0x3f),(name,row['text'])
                assert '__clac' not in row['text']
        patches=[];ida_bytes.visit_patched_bytes(0,ida_idaapi.BADADDR,lambda *args:patches.append(args) or 0);assert not patches
        result={'status':'PASS','cases':len(CASES),'ida':list(idapro.get_library_version()),'hexrays':hx.get_hexrays_version(),
            'plugin_sha256':sha(cfg['plugin']),'input_sha256':sha(cfg['binary']),'rows':rows,'operand_matrix':matrix_rows}
        Path(cfg['result']).write_text(json.dumps(result,indent=2))
        hx.clear_cached_cfuncs();ida_auto.auto_wait()
    finally:idapro.close_database(False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ida','plugin','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--vcvars',type=Path,default=Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'))
    a=p.parse_args();out=a.output.resolve();repo=Path(__file__).resolve().parents[1]
    if out.exists() or out==repo or repo in out.parents:p.error('use a fresh output directory outside the repository')
    out.mkdir(parents=True)
    source='.code\n'+''.join(f'{name} PROC\n {body}\n ret\n{name} ENDP\n' for name,body in CASES.items())+'END\n'
    (out/'fixture.asm').write_text(source);exports=' '.join('/export:'+name for name in CASES)
    (out/'build.bat').write_text(f'@call "{a.vcvars}" >nul 2>&1\n@cd /d "{out}"\n@ml64 /nologo /c fixture.asm && link /nologo /dll /noentry /subsystem:native /out:fixture.dll fixture.obj {exports}\n')
    with (out/'build.log').open('w') as log:subprocess.run(['cmd','/c',str(out/'build.bat')],check=True,stdout=log,stderr=subprocess.STDOUT,timeout=120)
    results=[]
    for mode in ('first','repeat'):
        work=out/mode;work.mkdir();shutil.copyfile(out/'fixture.dll',work/'fixture.dll')
        cfg={'ida':str(a.ida.resolve()),'plugin':str(a.plugin.resolve()),'binary':str(work/'fixture.dll'),'result':str(work/'result.json')}
        (work/'config.json').write_text(json.dumps(cfg));env=dict(os.environ,IDADIR=cfg['ida'],IDAUSR=str(work/'idausr'))
        with (work/'process.log').open('w') as log:subprocess.run([sys.executable,'-I',str(Path(__file__).resolve()),'--worker',str(work/'config.json')],check=True,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=120)
        results.append(json.loads((work/'result.json').read_text()))
    assert results[0]==results[1],'repeated decoder/lifter results differ'
    summary={'status':'PASS','cases':len(CASES),'operand_matrix_cases':len(results[0]['operand_matrix']),'repeat_differences':0,'plugin_sha256':sha(a.plugin),'script_sha256':sha(__file__)}
    (out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--worker':worker(json.loads(Path(sys.argv[2]).read_text()))
    else:main()
