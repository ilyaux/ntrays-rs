// C++ side of NtRays: everything that has to touch IDA SDK classes. Decisions are made in Rust (lib.rs);
// this file only forwards Hex-Rays events to Rust and builds microcode on Rust's request.
//
// Rule for every function Rust calls: catch all C++ exceptions here, so none unwinds through Rust frames.
#include <memory>
#include <vector>
#include <hexrays.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <kernwin.hpp>
#include <intel.hpp>
#include <xref.hpp>
#include <entry.hpp>

// ---------------------------------------------------------------------------------------------------------------
// Tables shared with Rust by index. lib.rs checks the names at load time (`ntrays_table_name`), so the order here
// and in Rust cannot drift apart silently. Raw NN_* / m_* values never cross into Rust: they differ between SDKs.
#define NTRAYS_INSNS( X ) \
	X( cpuid ) X( xgetbv ) X( xsetbv ) X( rdrand ) X( rdseed ) X( rdsspd ) X( rdsspq ) X( vmread ) X( rcl ) X( rcr ) \
	X( iretq ) X( sysret ) X( int ) \
	X( clac ) X( stac ) X( swapgs ) X( saveprevssp ) X( setssbsy ) X( endbr64 ) X( endbr32 ) X( incsspq ) X( incsspd ) \
	X( rstorssp ) X( wrssd ) X( wrssq ) X( wrussd ) X( wrussq ) X( clrssbsy ) X( clflushopt ) X( clwb ) X( vmclear ) \
	X( vmlaunch ) X( vmptrld ) X( vmptrst ) X( vmwrite ) X( vmxoff ) X( vmxon ) X( invept ) X( invvpid ) X( invpcid ) \
	X( invlpga ) X( xsaves ) X( xrstors ) X( prefetcht0 ) X( prefetcht1 ) X( prefetcht2 ) X( prefetchnta ) \
	X( lea ) X( nop ) X( mov ) X( syscall ) \
	X( vmfunc ) X( vmresume ) X( vmcall ) X( rdpid ) X( rdpkru ) X( wrpkru ) X( xsavec ) X( xsaveopt ) X( serialize ) \
	X( umonitor ) X( umwait ) X( tpause ) X( enqcmd ) X( uiret ) X( senduipi ) X( encls ) X( enclu )
#define NTRAYS_OPS( X ) X( mov ) X( add ) X( ldx ) X( stx ) X( low ) X( high ) X( xdu ) X( setz )

#define AS_NN( n ) NN_##n,
#define AS_M( n ) m_##n,
#define AS_NAME( n ) #n,
#define NTRAYS_MODERN_INSNS(X) X(erets) X(eretu) X(lkgs) X(wrmsrns) X(invlpgb) X(tlbsync)
enum : uint16 { MODERN_FIRST = CUSTOM_INSN_ITYPE + 0x4e0, MODERN_erets = MODERN_FIRST,
    MODERN_eretu, MODERN_lkgs, MODERN_wrmsrns, MODERN_invlpgb, MODERN_tlbsync };
#define AS_MODERN(n) MODERN_##n,
static const uint16 insn_itypes[] = { NTRAYS_INSNS( AS_NN ) NTRAYS_MODERN_INSNS(AS_MODERN) };
static const char* const insn_names[] = { NTRAYS_INSNS( AS_NAME ) NTRAYS_MODERN_INSNS(AS_NAME) };
static const mcode_t op_codes[] = { NTRAYS_OPS( AS_M ) };
static const char* const op_names[] = { NTRAYS_OPS( AS_NAME ) };

extern "C" const char* ntrays_table_name( uint32 table, uint32 i )
{
	if ( table == 0 ) return i < qnumber( insn_names ) ? insn_names[ i ] : nullptr;
	if ( table == 1 ) return i < qnumber( op_names ) ? op_names[ i ] : nullptr;
	return nullptr;
}

// msg() is an inline wrapper over callui() in the SDK, so Rust reaches it through here.
extern "C" void ntrays_msg( const char* text ) { msg( "%s", text ); }

// ---------------------------------------------------------------------------------------------------------------
// Rust entry points (lib.rs). `state` is the Rust plugin object for this database.
extern "C" void* ntrays_init();
extern "C" void ntrays_term( void* state );
extern "C" bool ntrays_run( void* state, size_t arg );
extern "C" bool ntrays_lift( void* state, void* builder, uint32 insn_kind );
// Should this operand fold to 0? `site` is Rust's `fold::Site`: 0 global read at `ea`, 1 call to `ea`,
// 2 `global(ea) & value`, 3 call statement to `ea` (removed with its setup).
extern "C" bool ntrays_fold( void* state, uint32 site, uint64 ea, uint64 value );
extern "C" void ntrays_names_changed( void* state );
extern "C" bool ntrays_component_enabled( void* state, uint32 component );

// ---------------------------------------------------------------------------------------------------------------
// Microcode builder: Rust refers to operands, types and calls by index into these arenas. Instructions are buffered
// and only inserted into the block if the Rust lifter succeeds, so a failed lift leaves no partial microcode.
static constexpr uint32 NONE = ~0u;

struct builder
{
	codegen_t& cg;
	std::vector<mop_t> mops;
	std::vector<tinfo_t> types;
	std::vector<std::unique_ptr<mcallinfo_t>> calls;
	std::vector<std::unique_ptr<minsn_t>> out;
	bool failed = false;

	uint32 add_mop( mop_t&& op ) { mops.emplace_back(); mops.back().swap( op ); return ( uint32 ) mops.size() - 1; }
	uint32 add_type( const tinfo_t& t ) { types.push_back( t ); return ( uint32 ) types.size() - 1; }
	bool bad( bool cond ) { failed |= cond; return cond; }
};

#define GUARDED( fallback, ... ) \
	try { __VA_ARGS__ } catch ( ... ) { b->failed = true; } return fallback;

extern "C" uint32 ntrays_mop_reg( builder* b, int reg, int size )  // x86 register (intel.hpp RegNo)
{
	GUARDED( NONE, mop_t op; op.make_reg( reg2mreg( reg ), size ); return b->add_mop( std::move( op ) ); )
}
extern "C" uint32 ntrays_mop_operand(builder* b, int opnum)
{
    GUARDED(NONE, const mreg_t r = b->cg.load_operand(opnum);
        if (b->bad(r == mr_none)) return NONE;
        mop_t op; op.make_reg(r, get_dtype_size(b->cg.insn.ops[opnum].dtype));
        return b->add_mop(std::move(op)); )
}
extern "C" uint32 ntrays_mop_kreg( builder* b, int size )  // fresh kernel (temporary) register
{
	GUARDED( NONE, mop_t op; op.make_reg( b->cg.mba->alloc_kreg( size ), size ); return b->add_mop( std::move( op ) ); )
}
extern "C" uint32 ntrays_mop_reg_pair( builder* b, int lo, int hi, int halfsize )  // hi:lo, e.g. edx:eax
{
	GUARDED( NONE, mop_t op; op.make_reg_pair( reg2mreg( lo ), reg2mreg( hi ), halfsize ); return b->add_mop( std::move( op ) ); )
}
static const mreg_t flag_regs[] = { mr_cf, mr_of, mr_zf, mr_sf, mr_pf };  // Rust `Flag` enum order
extern "C" uint32 ntrays_mop_flag( builder* b, uint32 flag )
{
	GUARDED( NONE,
		if ( b->bad( flag >= qnumber( flag_regs ) ) ) return NONE;
		mop_t op; op.make_reg( flag_regs[ flag ], 1 ); return b->add_mop( std::move( op ) ); )
}
extern "C" uint32 ntrays_mop_num( builder* b, uint64 value, int size )
{
	GUARDED( NONE, mop_t op; op.make_number( value, size ); return b->add_mop( std::move( op ) ); )
}
extern "C" uint32 ntrays_mop_ea( builder* b, int opnum )  // effective address of a memory operand, as a kreg
{
	GUARDED( NONE,
		mreg_t r = b->cg.load_effective_address( opnum );
		if ( b->bad( r == mr_none ) ) return NONE;
		int size = ad64( b->cg.insn ) ? 8 : ad32( b->cg.insn ) ? 4 : 2;
		mop_t op; op.make_reg( r, size );
		if ( size < 8 )
		{
			auto ins = std::make_unique<minsn_t>( b->cg.insn.ea );
			ins->opcode = m_xdu;
			ins->l.assign( op );
			ins->d.make_reg( b->cg.mba->alloc_kreg( 8 ), 8 );
			op.assign( ins->d );
			b->out.push_back( std::move( ins ) );
		}
		return b->add_mop( std::move( op ) ); )
}

// Builtin types, by the index of Rust's `Type` enum.
extern "C" uint32 ntrays_type_builtin( builder* b, uint32 kind )
{
	static const type_t bts[] = { BT_VOID, BT_INT8, BT_INT16, BT_INT32, BT_INT64, BT_INT128, BTF_FLOAT, BTF_DOUBLE };
	GUARDED( NONE,
		if ( kind == ( uint32 ) qnumber( bts ) )  // void*
		{
			tinfo_t t; t.create_ptr( tinfo_t{ BT_VOID } ); return b->add_type( t );
		}
		if ( b->bad( kind > qnumber( bts ) ) ) return NONE;
		return b->add_type( tinfo_t{ bts[ kind ] } ); )
}
// Named type from the database (e.g. "_MMPTE"), optionally as a pointer. NONE if the database lacks it.
extern "C" uint32 ntrays_type_named( builder* b, const char* name, bool pointer )
{
	GUARDED( NONE,
		tinfo_t t;
		if ( !t.get_named_type( get_idati(), name ) ) return NONE;
		if ( pointer ) { tinfo_t p; p.create_ptr( t ); t = p; }
		return b->add_type( t ); )
}

enum : uint32 { CALL_PURE = 1, CALL_NORET = 2, CALL_HASCALL = 4 };
extern "C" uint32 ntrays_call_new( builder* b, uint32 ret_type, uint32 flags )
{
	GUARDED( NONE,
		if ( b->bad( ret_type >= b->types.size() ) ) return NONE;
		auto ci = std::make_unique<mcallinfo_t>();
		ci->cc = CM_CC_FASTCALL;
		ci->callee = BADADDR;
		ci->solid_args = 0;
		ci->call_spd = 0;
		ci->stkargs_top = 0;
		ci->role = ROLE_UNK;
		ci->flags = FCI_FINAL | FCI_PROP;
		if ( flags & CALL_PURE ) ci->flags |= FCI_PURE;
		if ( flags & CALL_NORET ) ci->flags |= FCI_NORET;
		if ( flags & CALL_HASCALL ) ci->flags |= FCI_HASCALL;
		ci->return_type = b->types[ ret_type ];
		b->calls.push_back( std::move( ci ) );
		return ( uint32 ) b->calls.size() - 1; )
}
extern "C" void ntrays_call_arg( builder* b, uint32 call, uint32 mop, uint32 type, const char* name )
{
	GUARDED( ,
		if ( b->bad( call >= b->calls.size() || !b->calls[ call ] || mop >= b->mops.size() || type >= b->types.size() ) ) return;
		mcallarg_t arg;
		arg.assign( b->mops[ mop ] );
		arg.type = b->types[ type ];
		if ( name ) arg.name = name;
		b->calls[ call ]->args.push_back( arg ); )
}
extern "C" void ntrays_call_spoil( builder* b, uint32 call, int reg, int size )
{
	GUARDED( ,
		if ( b->bad( call >= b->calls.size() || !b->calls[ call ] ) ) return;
		b->calls[ call ]->spoiled.add( reg2mreg( reg ), size ); )
}
extern "C" void ntrays_call_spoil_flag( builder* b, uint32 call, uint32 flag )
{
	GUARDED( ,
		if ( b->bad( call >= b->calls.size() || !b->calls[ call ] || flag >= qnumber( flag_regs ) ) ) return;
		b->calls[ call ]->spoiled.add( flag_regs[ flag ], 1 ); )
}

// The call instruction `helper(args...)`; takes the call out of the arena.
static std::unique_ptr<minsn_t> take_call( builder* b, uint32 call, const char* helper )
{
	if ( b->bad( call >= b->calls.size() || !b->calls[ call ] ) ) return nullptr;
	auto ci = b->calls[ call ].release();
	auto ins = std::make_unique<minsn_t>( b->cg.insn.ea );
	ins->opcode = m_call;
	ins->l.make_helper( helper );
	ins->d.t = mop_f;
	ins->d.f = ci;
	ins->d.size = ci->return_type.is_void() ? 0 : ( int ) ci->return_type.get_size();
	return ins;
}
// The call's result as an operand (nested instruction).
extern "C" uint32 ntrays_mop_call( builder* b, uint32 call, const char* helper )
{
	GUARDED( NONE,
		auto ins = take_call( b, call, helper );
		if ( !ins ) return NONE;
		mop_t op; op.make_insn( ins.release() ); op.size = op.d->d.size;
		return b->add_mop( std::move( op ) ); )
}
// A call statement whose result is not used.
extern "C" void ntrays_emit_call( builder* b, uint32 call, const char* helper )
{
	GUARDED( , if ( auto ins = take_call( b, call, helper ) ) b->out.push_back( std::move( ins ) ); )
}
// `op l, r, d` with operands copied from the arena; NONE leaves an operand empty.
extern "C" void ntrays_emit( builder* b, uint32 op, uint32 l, uint32 r, uint32 d )
{
	GUARDED( ,
		if ( b->bad( op >= qnumber( op_codes ) ) ) return;
		auto ins = std::make_unique<minsn_t>( b->cg.insn.ea );
		ins->opcode = op_codes[ op ];
		mop_t* dst[] = { &ins->l, &ins->r, &ins->d };
		uint32 src[] = { l, r, d };
		for ( int i = 0; i != 3; i++ )
		{
			if ( src[ i ] == NONE ) continue;
			if ( b->bad( src[ i ] >= b->mops.size() ) ) return;
			dst[ i ]->assign( b->mops[ src[ i ] ] );
		}
		b->out.push_back( std::move( ins ) ); )
}

// Read access to the instruction being lifted.
struct op_info { uint8 type, dtype; uint16 reg; uint64 value, addr; };
struct insn_info { uint64 ea; uint32 size; op_info ops[ 8 ]; };
extern "C" void ntrays_insn( builder* b, insn_info* out )
{
	const insn_t& in = b->cg.insn;
	out->ea = in.ea;
	out->size = in.size;
	for ( int i = 0; i != 8; i++ )
		out->ops[ i ] = { in.ops[ i ].type, in.ops[ i ].dtype, in.ops[ i ].reg, in.ops[ i ].value, in.ops[ i ].addr };
}

// Name of the function being decompiled; returns its length (truncated to `size - 1`).
extern "C" size_t ntrays_func_name( builder* b, char* buf, size_t size )
{
	try { return qstrncpy( buf, get_name( b->cg.mba->entry_ea ).c_str(), size ) ? strlen( buf ) : 0; } catch ( ... ) { return 0; }
}
// A type from a C declaration such as "PHANDLE" or "ULONG" against the database's types; NONE if it does not parse.
extern "C" uint32 ntrays_type_decl( builder* b, const char* decl )
{
	GUARDED( NONE,
		tinfo_t t;
		qstring name, text = decl;
		text.append( ';' );
		if ( !parse_decl( &t, &name, nullptr, text.c_str(), PT_SIL | PT_TYP ) ) return NONE;
		return b->add_type( t ); )
}
extern "C" int ntrays_type_size( builder* b, uint32 type )
{
	GUARDED( 0,
		if ( b->bad( type >= b->types.size() ) ) return 0;
		size_t size = b->types[ type ].get_size();
		return size == BADSIZE ? 0 : ( int ) size; )
}
// `name *__shifted(name, delta)`: a pointer `delta` bytes into a `name`. NONE if the database lacks the type.
extern "C" uint32 ntrays_type_shifted_ptr( builder* b, const char* name, int delta )
{
	GUARDED( NONE,
		tinfo_t t;
		if ( !t.get_named_type( get_idati(), name ) ) return NONE;
		ptr_type_data_t pi;
		pi.obj_type = t;
		pi.parent = t;
		pi.delta = delta;
		pi.taptr_bits = TAPTR_SHIFTED;
		tinfo_t p; p.create_ptr( pi );
		return b->add_type( p ); )
}

// ---------------------------------------------------------------------------------------------------------------
// Database-level helpers (called from Rust outside of decompilation).
extern "C" bool ntrays_db_is_pe64() { return inf_get_filetype() == f_PE && inf_is_64bit(); }

// First match of `pattern` at or after `start`, or ~0 if none.
extern "C" uint64 ntrays_db_find_bytes( uint64 start, const uint8* pattern, size_t size )
{
	try
	{
		ea_t ea = bin_search( start, inf_get_max_ea(), pattern, nullptr, size, BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK );
		return ea == BADADDR ? ~0ull : ea;
	}
	catch ( ... ) { return ~0ull; }
}
// Patches bytes the way Edit > Patch program does (originals are kept and can be reverted) and re-analyzes them.
extern "C" void ntrays_db_patch( uint64 ea, const uint8* bytes, size_t size )
{
	try
	{
		del_items( ea, DELIT_SIMPLE, size );
		patch_bytes( ea, bytes, size );
		auto_make_code( ea );
		plan_range( ea, ea + size );
	}
	catch ( ... ) {}
}
extern "C" uint64 ntrays_db_min_ea() { return inf_get_min_ea(); }
extern "C" uint64 ntrays_db_name_ea( const char* name )
{
	try { ea_t ea = get_name_ea( BADADDR, name ); return ea == BADADDR ? ~0ull : ea; } catch ( ... ) { return ~0ull; }
}

// Per-database settings, stored in the IDB (netnode "$ ntrays-rs", altval by index).
static netnode settings_node() { return netnode( "$ ntrays-rs", 0, true ); }
extern "C" uint64 ntrays_db_setting( uint32 idx ) { try { return settings_node().altval( idx ); } catch ( ... ) { return 0; } }
extern "C" void ntrays_db_set_setting( uint32 idx, uint64 value ) { try { settings_node().altset( idx, value ); } catch ( ... ) {} }
extern "C" bool ntrays_db_settings_read( uint64* value )
{
    try { netnode node("$ ntrays-rs"); *value = node == BADNODE ? 0 : node.altval(3); return true; }
    catch ( ... ) { return false; }
}
extern "C" bool ntrays_db_settings_write( uint64 value )
{
    try { netnode node = settings_node(); return node.altset(3, value) && node.altval(3) == value; }
    catch ( ... ) { return false; }
}

// Bytes from the database; returns how many were read.
extern "C" size_t ntrays_get_bytes( uint64 ea, uint8* buf, size_t size )
{
	try { ssize_t n = get_bytes( buf, size, ea ); return n > 0 ? ( size_t ) n : 0; } catch ( ... ) { return 0; }
}

// Syscall state is owned by the current IDB. The old node is read-only migration input.
static constexpr size_t SYSCALL_BLOB_LIMIT = 8 * 1024 * 1024;
static netnode syscall_node( bool create = false ) { return netnode( "$ ntrays-rs syscall", 0, create ); }
extern "C" ssize_t ntrays_db_syscall_read( uint32 kind, uint64 ea, uint8* buf, size_t cap )
{
	try
	{
		netnode node = kind == 1 ? netnode( "$ ntrays syscall" ) : syscall_node();
		if ( node == BADNODE ) return -1;
		if ( kind == 2 ) return node.supval_ea( ea, buf, cap, 'S' );
		nodeidx_t slot = 0;
		if ( kind == 0 )
		{
			nodeidx_t active = node.altval( 0 );
			if ( !active ) return -1;
			if ( active > 2 ) return -2;
			slot = active - 1;
		}
		else if ( kind != 1 ) return -2;
		size_t size = node.blobsize( slot, 'B' );
		if ( size > SYSCALL_BLOB_LIMIT ) return -2;
		if ( !buf ) return size;
		if ( cap < size || !size ) return -2;
		size_t actual = cap;
		return node.getblob( buf, &actual, slot, 'B' ) && actual == size ? ssize_t( size ) : -2;
	}
	catch ( ... ) { return -2; }
}
extern "C" bool ntrays_db_syscall_write( uint32 kind, uint64 ea, const uint8* data, size_t size )
{
	try
	{
		if ( !data || !size || size > SYSCALL_BLOB_LIMIT ) return false;
		netnode node = syscall_node( true );
		if ( kind == 2 ) return size <= MAXSPECSIZE && node.supset_ea( ea, data, size, 'S' );
		if ( kind != 0 ) return false;
		nodeidx_t active = node.altval( 0 );
		if ( active > 2 ) return false;
		nodeidx_t slot = active == 1 ? 1 : 0;
		if ( !node.setblob( data, size, slot, 'B' ) ) return false;
		bytevec_t check;
		if ( node.getblob( &check, slot, 'B' ) != ssize_t( size ) || memcmp( check.begin(), data, size ) ) return false;
		return node.altset( 0, slot + 1 );  // commit only after the inactive blob has been verified
	}
	catch ( ... ) { return false; }
}
extern "C" uint64 ntrays_db_syscall_legacy_selection()
{
	try { netnode node( "$ ntrays syscall" ); return node == BADNODE ? 0 : node.altval( 0 ); } catch ( ... ) { return 0; }
}
extern "C" uint64 ntrays_db_syscall_legacy_site( uint64 ea )
{
	try { netnode node( "$ ntrays syscall" ); return node == BADNODE ? 0 : node.altval_ea( ea ); } catch ( ... ) { return 0; }
}
extern "C" bool ntrays_db_syscall_legacy_confirmed( const uint8* expected, size_t size )
{
	try
	{
		netnode node = syscall_node();
		if ( node == BADNODE ) return false;
		qstring profile;
		return node.supstr( &profile, 0, 'M' ) == ssize_t( size ) && profile.length() == size
			&& memcmp( profile.c_str(), expected, size ) == 0;
	}
	catch ( ... ) { return false; }
}
extern "C" size_t ntrays_db_syscall_exports()
{
	try
	{
		if ( !ntrays_db_is_pe64() ) return 0;
		char name[ QMAXPATH ] = {};
		if ( get_root_filename( name, sizeof( name ) ) <= 0 ) return 0;
		return stricmp( name, "ntdll.dll" ) == 0 || stricmp( name, "win32u.dll" ) == 0 ? get_entry_qty() : 0;
	}
	catch ( ... ) { return 0; }
}
extern "C" ssize_t ntrays_db_syscall_export( size_t index, uint32* number, char* name, size_t cap )
{
	try
	{
		if ( index >= get_entry_qty() ) return -1;
		uval_t ord = get_entry_ordinal( index );
		ea_t ea = get_entry( ord );
		uint8 stub[ 8 ];
		static const uint8 head[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
		if ( ea == BADADDR || get_bytes( stub, sizeof( stub ), ea ) != sizeof( stub ) || memcmp( stub, head, sizeof( head ) ) ) return -1;
		qstring text;
		ssize_t len = get_entry_name( &text, ord );
		if ( len <= 0 || size_t( len ) >= cap ) return -1;
		memcpy( number, stub + 4, sizeof( *number ) );
		qstrncpy( name, text.c_str(), cap );
		return len;
	}
	catch ( ... ) { return -1; }
}

// ---------------------------------------------------------------------------------------------------------------
// Hex-Rays hooks: one of each kind, all forwarding to Rust.
struct dispatch_filter : microcode_filter_t
{
	void* state;
	uint8 kind_of[ 0x10000 ];  // itype -> kind + 1, 0 = not ours; makes match() a table lookup
	explicit dispatch_filter( void* s ) : state( s )
	{
		memset( kind_of, 0, sizeof( kind_of ) );
		for ( size_t i = 0; i != qnumber( insn_itypes ); i++ ) kind_of[ insn_itypes[ i ] ] = ( uint8 ) ( i + 1 );
	}
	bool match( codegen_t& cg ) override
	{
		if ( !kind_of[ cg.insn.itype ] )
			return false;
        const uint32 component = cg.insn.itype == NN_syscall
            || (cg.insn.itype == NN_int && cg.insn.ops[0].value == 0x2e) ? 1
            : cg.insn.itype == NN_nop ? 4 : 0;
        if ( !ntrays_component_enabled(state, component) ) return false;
		// `mov` is everywhere; only `mov reg, imm64` can be a paging relocation, so keep the rest out of Rust.
		if ( cg.insn.itype == NN_mov )
			return cg.insn.ops[ 0 ].type == o_reg && cg.insn.ops[ 1 ].type == o_imm && cg.insn.ops[ 1 ].dtype == dt_qword;
		return true;
	}
	merror_t apply( codegen_t& cg ) override
	{
		builder b{ cg };
		if ( !ntrays_lift( state, &b, kind_of[ cg.insn.itype ] - 1 ) || b.failed )
			return MERR_INSN;  // fall back to Hex-Rays' own lifting; buffered instructions are discarded
		for ( auto& ins : b.out ) cg.mb->insert_into_block( ins.release(), cg.mb->tail );
		cg.mb->mark_lists_dirty();
		return MERR_OK;
	}
};
static_assert( qnumber( insn_itypes ) < 255 );

enum : uint32 { SITE_GLOBAL, SITE_CALL, SITE_AND, SITE_CALL_STATEMENT };

// Folds operands of conditional jumps that read instrumentation / hint globals (Rust decides which).
// Only real global operands (mop_v) are considered: the original read `op->g` from operands of any type.
struct fold_visitor : mop_visitor_t
{
	void* state;
	int changes = 0;
	explicit fold_visitor( void* s ) : state( s ) {}
	int idaapi visit_mop( mop_t* op, const tinfo_t*, bool ) override
	{
		bool fold = false;
		if ( op->t == mop_v )
			fold = ntrays_fold( state, SITE_GLOBAL, op->g, 0 );
		else if ( op->t == mop_d && op->d->opcode == m_call && op->d->l.t == mop_v )
			fold = ntrays_fold( state, SITE_CALL, op->d->l.g, 0 );
		else if ( op->t == mop_d && op->d->opcode == m_and )
		{
			const mop_t* g = &op->d->l;
			const mop_t* n = &op->d->r;
			if ( g->t == mop_n ) std::swap( g, n );
			if ( g->t == mop_v && n->t == mop_n )
				fold = ntrays_fold( state, SITE_AND, g->g, n->nnn->value );
		}
		if ( !fold || op->size <= 0 )
			return 0;
		op->make_number( 0, op->size );
		changes++;
		return 1;  // the operand tree changed under us; stop this walk
	}
};

struct dispatch_optinsn : optinsn_t
{
	void* state;
	explicit dispatch_optinsn( void* s ) : state( s ) {}
	int idaapi func( mblock_t* blk, minsn_t* ins, int ) override
	{
		if ( !ntrays_component_enabled(state, 2) ) return 0;
		if ( !is_mcode_jcond( ins->opcode ) )
			return 0;
		fold_visitor v( state );
		ins->for_all_ops( v );
		if ( v.changes && blk )
			blk->mark_lists_dirty();
		return v.changes;
	}
};

// Removes scheduler-hint call statements together with the code in the predecessor blocks that sets them up
// (everything but the predecessors' final jumps), as the original did.
struct dispatch_optblock : optblock_t
{
	void* state;
	explicit dispatch_optblock( void* s ) : state( s ) {}
	int idaapi func( mblock_t* blk ) override
	{
		if ( !ntrays_component_enabled(state, 2) ) return 0;
		int changes = 0;
		for ( minsn_t* ins = blk->head; ins; ins = ins->next )
		{
			if ( ins->opcode != m_call || ins->l.t != mop_v || !ntrays_fold( state, SITE_CALL_STATEMENT, ins->l.g, 0 ) )
				continue;
			blk->make_nop( ins );
			changes++;
			for ( int i = 0; i != blk->npred(); i++ )
			{
				mblock_t* pred = blk->mba->get_mblock( blk->pred( i ) );
				for ( minsn_t* p = pred->head; p; p = p->next )
					if ( p != pred->tail )
						pred->make_nop( p );
			}
		}
		return changes;
	}
};

// ---------------------------------------------------------------------------------------------------------------
// KUSER_SHARED_DATA segment. Only the mapping the binary uses is created (kernel: 0xFFFFF78000000000, user:
// 0x7FFE0000): the original always created both, and the user one at 0x7FFE0000 has no room to move down, which
// made Rebase Program fail on ntoskrnl (upstream issue 3). The segment is fixed in memory, so it is removed before
// a rebase and put back at its address afterwards.
static const char* kuser_seg_name() { return inf_is_kernel_mode() ? ".kkuser" : ".ukuser"; }
static ea_t kuser_ea() { return inf_is_kernel_mode() ? 0xFFFFF78000000000ull : 0x7FFE0000ull; }

static void drop_kuser()
{
	if ( segment_t* s = get_segm_by_name( kuser_seg_name() ) )
		del_segm( s->start_ea, SEGMOD_KILL | SEGMOD_SILENT );
}
static void ensure_kuser()
{
	const ea_t ea = kuser_ea();
	segment_t* s = get_segm_by_name( kuser_seg_name() );
	if ( s && s->start_ea == ea ) return;
	if ( s ) drop_kuser();  // moved by a rebase
	if ( getseg( ea ) ) return;  // something else lives there already
	if ( !add_segm( 0x1000, ea, ea + 0x1000, kuser_seg_name(), inf_is_kernel_mode() ? "DATA" : "CONST" ) ) return;
	set_name( ea, "KUSER_SHARED_DATA", SN_NOWARN | SN_FORCE );
	tinfo_t t;
	if ( t.get_named_type( get_idati(), "_KUSER_SHARED_DATA" ) )
		create_struct( ea, t.get_size(), t.get_tid(), true );
}
extern "C" void ntrays_db_set_kuser_wanted(bool enabled)
{
    // Existing mappings remain database data when disabled; only future creation is gated.
    try { if ( enabled ) ensure_kuser(); } catch ( ... ) {}
}

// ---------------------------------------------------------------------------------------------------------------
// Parent types: `_KTHREAD *` -> `_ETHREAD *` (and _KPROCESS -> _EPROCESS) in local variables and struct fields.
// Pairs come from Rust. Only pointers are rewritten (at any depth): a struct embedding _KTHREAD by value, like
// _ETHREAD.Tcb, must keep it.
static std::vector<std::pair<qstring, qstring>> parent_type_names;
extern "C" void ntrays_add_parent_type( const char* child, const char* parent )
{
	try
    {
        for ( const auto& pair : parent_type_names )
            if ( pair.first == child && pair.second == parent ) return;
        parent_type_names.emplace_back( child, parent );
    }
    catch ( ... ) {}
}
static std::vector<std::pair<tinfo_t, tinfo_t>> parent_types()
{
	std::vector<std::pair<tinfo_t, tinfo_t>> out;
	for ( auto& [c, p] : parent_type_names )
	{
		tinfo_t ct, pt;
		if ( ct.get_named_type( get_idati(), c.c_str() ) && pt.get_named_type( get_idati(), p.c_str() ) )
			out.emplace_back( ct, pt );
	}
	return out;
}
// Rewrites pointer targets in `t`; returns whether anything changed. (The original handled one pointer level.)
static bool retype_pointers( tinfo_t& t, const std::vector<std::pair<tinfo_t, tinfo_t>>& pairs )
{
	if ( !t.is_ptr() ) return false;
	ptr_type_data_t pi;
	if ( !t.get_ptr_details( &pi ) ) return false;
	bool changed = false;
	for ( auto& [child, parent] : pairs )
	{
		if ( pi.obj_type == child ) { pi.obj_type = parent; changed = true; }
		if ( pi.parent == child ) { pi.parent = parent; changed = true; }
	}
	changed |= retype_pointers( pi.obj_type, pairs );
	if ( changed ) { tinfo_t n; n.create_ptr( pi ); t = n; }
	return changed;
}
// Struct and union fields in the database's types; returns how many fields changed.
extern "C" int ntrays_db_fix_parent_types()
{
	try
	{
		auto pairs = parent_types();
		if ( pairs.empty() ) return 0;
		const til_t* til = get_idati();
		std::vector<qstring> names;
		for ( const char* n = first_named_type( til, NTF_TYPE ); n; n = next_named_type( til, n, NTF_TYPE ) )
			names.push_back( n );
		int fixed = 0;
		for ( auto& name : names )
		{
			tinfo_t ti;
			udt_type_data_t udt;
			if ( !ti.get_named_type( til, name.c_str() ) || !ti.is_udt() || !ti.get_udt_details( &udt ) ) continue;
			for ( size_t i = 0; i != udt.size(); i++ )
			{
				tinfo_t ft = udt[ i ].type;
				if ( retype_pointers( ft, pairs ) && ti.set_udm_type( i, ft ) == TERR_OK )
					fixed++;
			}
		}
		return fixed;
	}
	catch ( ... ) { return 0; }
}
static void fix_lvar_types( cfunc_t* cf )
{
	auto pairs = parent_types();
	if ( pairs.empty() ) return;
	for ( lvar_t& v : cf->mba->vars )  // the original walked this list once per basic block
	{
		tinfo_t t = v.type();
		if ( retype_pointers( t, pairs ) )
			v.set_lvar_type( t );
	}
}

// KiKernelExit consumes the hardware IRET frame at RSP, not Win64 stack arguments. Otherwise Hex-Rays
// invents a fifth argument in its callers and later fails to analyze calls to KiRestoreSetContextState.
static void fix_kernel_exit_type()
{
	try
	{
		if ( !ntrays_db_is_pe64() || !inf_is_kernel_mode() ) return;
		ea_t ea = get_name_ea( BADADDR, "KiKernelExit" );
		if ( ea == BADADDR || is_userti( ea ) ) return;
		func_t* f = get_func( ea );
		if ( !f || f->start_ea != ea ) return;
		// push rax; push rdx; lea rax,[rsp+38h]: RAX points past the five-qword IRET frame.
		static const uint8 prefix[] = { 0x50, 0x52, 0x48, 0x8D, 0x44, 0x24, 0x38 };
		uint8 bytes[ sizeof( prefix ) ];
		if ( get_bytes( bytes, sizeof( bytes ), ea ) != sizeof( bytes ) || memcmp( bytes, prefix, sizeof( prefix ) ) ) return;
		tinfo_t ti;
		qstring name;
		if ( !parse_decl( &ti, &name, nullptr, "void __usercall __noreturn KiKernelExit(void *frame@<rsp>);", PT_SIL )
			|| !apply_tinfo( ea, ti, TINFO_DEFINITE ) ) return;
		// Existing databases can retain the bogus argument lists inferred before the exit ABI was known.
		for ( ea_t from = get_first_fcref_to( ea ); from != BADADDR; from = get_next_fcref_to( ea, from ) )
		{
			func_t* caller = get_func( from );
			if ( caller && !is_userti( caller->start_ea ) && is_type_guessed_by_hexrays( caller->start_ea ) )
			{
				del_tinfo( caller->start_ea );
				mark_cfunc_dirty( caller->start_ea, false );
			}
		}
	}
	catch ( ... ) {}
}

extern "C" void ntrays_db_apply_kernel_exit_type()
{
    fix_kernel_exit_type();
}

#include "settings_ui.hpp"
#include "syscall_ui.hpp"
#include "literals.hpp"
#include "decoder.hpp"

struct ntrays_event_context
{
    void* state;
    syscall_actions* actions;
};

static ssize_t idaapi hexrays_events( void* user_data, hexrays_event_t event, va_list va )
{
	try
	{
        auto* context = static_cast<ntrays_event_context*>(user_data);
        void* state = context->state;
		if ( event == hxe_populating_popup )
        {
            TWidget* widget = va_arg(va, TWidget*);
            TPopupMenu* popup = va_arg(va, TPopupMenu*);
            vdui_t* vu = va_arg(va, vdui_t*);
            context->actions->popup(widget, popup, vu);
        }
		else if ( event == hxe_microcode && ntrays_component_enabled(state, 3) )  // also handles late PDB names
			fix_kernel_exit_type();
		else if ( event == hxe_maturity && ntrays_component_enabled(state, 3) )
		{
			cfunc_t* cf = va_arg( va, cfunc_t* );
			const auto maturity = ctree_maturity_t( va_arg( va, int ) );
			if ( maturity == CMAT_ZERO )
				fix_lvar_types( cf );
            else if ( maturity == CMAT_FINAL )
                format_windows_literals( cf );
		}
	}
	catch ( ... ) {}
	return 0;
}

// Tells Rust when names change (its name -> address cache), and keeps the KUSER segment in place across rebases.
struct idb_listener : event_listener_t
{
	void* state;
	explicit idb_listener( void* s ) : state( s ) {}
	ssize_t idaapi on_event( ssize_t code, va_list ) override
	{
		if ( code == idb_event::renamed )
			ntrays_names_changed( state );
		else if ( code == idb_event::allsegs_moved )
        {
            ntrays_names_changed(state);
            if ( ntrays_component_enabled(state, 5) || get_segm_by_name(kuser_seg_name()) ) ensure_kuser();
        }
		return 0;
	}
};
struct ui_listener : event_listener_t
{
    void* state;
    bool rebase_mapping = false;
    explicit ui_listener(void* s) : state(s) {}
	ssize_t idaapi on_event( ssize_t code, va_list va ) override
	{
		if ( code != ui_preprocess_action && code != ui_postprocess_action ) return 0;
		const char* action = va_arg( va, const char* );
		if ( !action || strcmp( action, "RebaseProgram" ) != 0 ) return 0;
        if ( code == ui_preprocess_action )
        {
            // Preserve a mapping already in the IDB even when future mapping creation is disabled.
            rebase_mapping = get_segm_by_name(kuser_seg_name()) != nullptr;
            if ( rebase_mapping ) drop_kuser();
        }
        else if ( rebase_mapping || ntrays_component_enabled(state, 5) )
        {
            ensure_kuser();
            rebase_mapping = false;
        }
		return 0;
	}
};

// ---------------------------------------------------------------------------------------------------------------
// Plugin object: one per database. Hooks are installed for the plugmod's lifetime.
struct ntrays_plugmod : plugmod_t
{
	void* state;
	modern_decoder decoder; // destroyed last, after Hex-Rays releases its instruction trees
	dispatch_filter filter;
	dispatch_optinsn optinsn;
	dispatch_optblock optblock;
	idb_listener names;
	ui_listener ui;
    std::unique_ptr<syscall_actions> syscalls_ui;
    ntrays_event_context events;

	explicit ntrays_plugmod( void* s ) : state( s ), decoder(this), filter( s ), optinsn( s ), optblock( s ), names( s ), ui( s ),
        syscalls_ui(std::make_unique<syscall_actions>(s, this)), events{ s, syscalls_ui.get() }
	{
		hook_event_listener( HT_IDB, &names );  // owned by this plugmod
		hook_event_listener( HT_UI, &ui );
		install_microcode_filter( &filter, true );
		install_optinsn_handler( &optinsn );
		install_optblock_handler( &optblock );
		install_hexrays_callback( hexrays_events, &events );
		clear_cached_cfuncs();
	}
	~ntrays_plugmod() override
	{
		remove_hexrays_callback( hexrays_events, &events );
		clear_cached_cfuncs();
		remove_optblock_handler( &optblock );
		remove_optinsn_handler( &optinsn );
		install_microcode_filter( &filter, false );
		unhook_event_listener( HT_UI, &ui );
		unhook_event_listener( HT_IDB, &names );
        syscalls_ui.reset();
		ntrays_term( state );
		term_hexrays_plugin();
	}
	bool idaapi run( size_t arg ) override { return ntrays_run( state, arg ); }
};

static plugmod_t* idaapi init()
{
	if ( !init_hexrays_plugin() )
		return nullptr;
	void* state = ntrays_init();
	if ( !state )
	{
		term_hexrays_plugin();
		return nullptr;
	}
	return new ntrays_plugmod( state );
}

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, PLUGIN_MULTI, init, nullptr, nullptr,
	"NtRays: Hex-Rays cleanup for Windows kernel code", nullptr, "NtRays", "Alt-F8",
};
