// THE OBJECT LANE. The source lane reads what the operator wrote; this reads
// what the compiler made of it -- an object's instructions after optimization
// -- and emits the same D, G, R, B and E records into the same artifact, so
// nothing about the reader changes. The two answer different questions and
// neither substitutes for the other: The source lane cannot see what the
// optimizer folded away or duplicated, and this lane cannot say which predicate
// a branch was written as. It is also the durable one: An instruction set is a
// stable contract, where a language's syntax is not.
//
// ONE EMITTER, ONE DECODER PER MACHINE. A decoder says only what each
// instruction does to control flow -- straight, a conditional jump, a goto, a
// return, a call, an indirect jump, data -- with its target and, for a
// conditional, the comparison it makes. Everything else is shared: Splitting
// blocks at targets and after jumps, the edges, the guards' depth, and the
// records. BPF, aarch64 and x86-64 are read, x86-64 through a length decoder
// over its prefixes, opcode maps and operand forms, since nothing else says
// where one of its instructions ends.
//
// WHAT THE ROWS MEAN HERE. A function is an STT_FUNC symbol in an executable
// section, and a block's "line" is an instruction index within that section,
// since object code has no lines of its own. A guard is a conditional jump, its
// text the comparison it makes (`r1 > 5`, `x3 == 0`, `ne`), its depth the number
// of conditional blocks that dominate it -- the nearest thing to the source
// lane's nesting the instructions carry. A declaration is a function, or a BPF
// map; a reference is a call, a tail call, or a BPF map's address loaded into a
// register, so the join can say what reaches what.
//
// The graph keeps the source lane's shape: Block 0 is the entry, block 1 the
// exit every return goes to, and the instruction blocks follow in order.
#include "static_object.hpp"

#include <elf.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "sublimation_order.hpp"
#include "util/Procfs.hpp"

namespace {

struct Sec {
  std::string name;
  uint32_t type = 0;
  uint64_t flags = 0, addr = 0, off = 0, size = 0;
  uint32_t link = 0, info = 0;
};

struct Sym { std::string name; uint8_t type = 0, bind = 0; uint16_t shndx = 0; uint64_t value = 0, size = 0; };

struct Reloc { const Sym* sym; uint32_t type; int64_t addend; };

struct Image {
  std::string img;
  Elf64_Ehdr eh{};
  std::vector<Sec> secs;
  std::vector<Sym> syms;
  std::map<std::pair<size_t, uint64_t>, Reloc> reloc;   // (section, byte offset)
  std::set<std::string> dyn_exports;   // functions .dynsym defines: what a linked object exports
};

template <class T> bool at(const std::string& img, uint64_t off, T& out) {
  if (off > img.size() || img.size() - off < sizeof(T)) return false;
  std::memcpy(&out, img.data() + off, sizeof(T));
  return true;
}

std::string cstr(const std::string& img, const Sec& strtab, uint32_t off) {
  if (off >= strtab.size || strtab.off + off >= img.size()) return {};
  const char* s = img.data() + strtab.off + off;
  const size_t max = std::min<uint64_t>(strtab.size - off, img.size() - strtab.off - off);
  return std::string(s, strnlen(s, max));
}

bool load(const std::string& path, Image& im, std::string& err) {
  auto img = montauk::util::read_file_string(path);
  if (!img) { err = "cannot read"; return false; }
  im.img = std::move(*img);
  if (!at(im.img, 0, im.eh) || im.eh.e_ident[EI_DATA] != ELFDATA2LSB) {
    err = "not a little-endian ELF64 object";
    return false;
  }
  im.secs.resize(im.eh.e_shnum);
  std::vector<uint32_t> names(im.secs.size());
  for (size_t k = 0; k < im.secs.size(); ++k) {
    Elf64_Shdr sh{};
    if (!at(im.img, im.eh.e_shoff + k * sizeof sh, sh)) { err = "truncated section headers"; return false; }
    im.secs[k] = {{}, sh.sh_type, sh.sh_flags, sh.sh_addr, sh.sh_offset, sh.sh_size, sh.sh_link, sh.sh_info};
    names[k] = sh.sh_name;
  }
  if (im.eh.e_shstrndx >= im.secs.size()) { err = "no section name table"; return false; }
  for (size_t k = 0; k < im.secs.size(); ++k) im.secs[k].name = cstr(im.img, im.secs[im.eh.e_shstrndx], names[k]);
  // .symtab, or .dynsym when a linked object was stripped of it.
  for (uint32_t want : {(uint32_t)SHT_SYMTAB, (uint32_t)SHT_DYNSYM}) {
    for (const Sec& s : im.secs) {
      if (s.type != want || s.link >= im.secs.size()) continue;
      for (uint64_t o = 0; o + sizeof(Elf64_Sym) <= s.size; o += sizeof(Elf64_Sym)) {
        Elf64_Sym e{};
        if (!at(im.img, s.off + o, e)) break;
        im.syms.push_back({cstr(im.img, im.secs[s.link], e.st_name), (uint8_t)ELF64_ST_TYPE(e.st_info),
                           (uint8_t)ELF64_ST_BIND(e.st_info), e.st_shndx, e.st_value, e.st_size});
      }
    }
    if (!im.syms.empty()) break;
  }
  for (const Sec& s : im.secs) {
    if (s.type != SHT_DYNSYM || s.link >= im.secs.size()) continue;
    for (uint64_t o = 0; o + sizeof(Elf64_Sym) <= s.size; o += sizeof(Elf64_Sym)) {
      Elf64_Sym e{};
      if (!at(im.img, s.off + o, e)) break;
      if (ELF64_ST_TYPE(e.st_info) == STT_FUNC && e.st_shndx != SHN_UNDEF)
        im.dyn_exports.insert(cstr(im.img, im.secs[s.link], e.st_name));
    }
  }
  for (const Sec& s : im.secs) {
    const bool rela = s.type == SHT_RELA;
    if ((s.type != SHT_REL && !rela) || s.info >= im.secs.size()) continue;
    const uint64_t ent = rela ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
    for (uint64_t o = 0; o + ent <= s.size; o += ent) {
      Elf64_Rela r{};
      if (rela) {
        if (!at(im.img, s.off + o, r)) break;
      } else {
        Elf64_Rel rr{};
        if (!at(im.img, s.off + o, rr)) break;
        r.r_offset = rr.r_offset; r.r_info = rr.r_info;
      }
      const size_t si = ELF64_R_SYM(r.r_info);
      if (si < im.syms.size())
        im.reloc[{s.info, r.r_offset}] = {&im.syms[si], (uint32_t)ELF64_R_TYPE(r.r_info), rela ? r.r_addend : 0};
    }
  }
  return true;
}

// What one instruction does to control flow, in instruction slots.
struct Op {
  enum Kind { Straight, Cond, Goto, Return, Call, Indirect } kind = Straight;
  int width = 1;
  long target = -1;          // Cond, Goto, Call: the slot it reaches, when direct
  std::string text;          // Cond: the comparison
  std::string ref;           // a name this instruction reaches: callee, tail call, map
};

struct Fn { size_t sec; long start, end; std::string name; bool entered; };

// THE MACHINES. Each sees the image, a section and a slot, and the functions,
// so a direct call can be named by the function at its target.
struct Machine {
  const char* dialect;
  int slot_bytes;
  bool (*decls_map)(const Image&, const Sym&);   // extra declarations: BPF maps
  Op (*decode)(const Image&, size_t sec, long slot, const std::vector<Fn>& fns);
};

const Fn* fn_at(const std::vector<Fn>& fns, size_t sec, long slot) {
  for (const Fn& f : fns) if (f.sec == sec && f.start == slot) return &f;
  return nullptr;
}

const Reloc* reloc_at(const Image& im, size_t sec, uint64_t byte) {
  auto r = im.reloc.find({sec, byte});
  return r == im.reloc.end() ? nullptr : &r->second;
}

bool is_maps_sec(const Image& im, uint16_t shndx) {
  return shndx < im.secs.size() && (im.secs[shndx].name == ".maps" || im.secs[shndx].name == "maps");
}

// BPF: Eight-byte slots, ld_imm64 two of them.
const char* bpf_cond(uint8_t op) {
  switch (op) {
    case 0x10: return "==";
    case 0x20: return ">";
    case 0x30: return ">=";
    case 0x40: return "&";
    case 0x50: return "!=";
    case 0x60: return "s>";
    case 0x70: return "s>=";
    case 0xa0: return "<";
    case 0xb0: return "<=";
    case 0xc0: return "s<";
    case 0xd0: return "s<=";
    default: return nullptr;
  }
}

Op bpf_decode(const Image& im, size_t sec, long slot, const std::vector<Fn>& fns) {
  Op op;
  const Sec& s = im.secs[sec];
  uint8_t raw[8];
  if (!at(im.img, s.off + (uint64_t)slot * 8, raw)) return op;
  const uint8_t code = raw[0], dst = raw[1] & 0x0f, src = raw[1] >> 4;
  int16_t off; int32_t imm;
  std::memcpy(&off, raw + 2, 2);
  std::memcpy(&imm, raw + 4, 4);
  const uint8_t cls = code & 7, opc = code & 0xf0;
  const bool jmp = cls == 0x05 || cls == 0x06;
  const Reloc* r = reloc_at(im, sec, (uint64_t)slot * 8);
  if (code == 0x18) {
    op.width = 2;
    if (r && is_maps_sec(im, r->sym->shndx)) op.ref = r->sym->name;
  } else if (code == 0x95) {
    op.kind = Op::Return;
  } else if (code == 0x85) {
    op.kind = Op::Call;
    if (src == 1) {
      if (r && r->sym->type == STT_FUNC) op.ref = r->sym->name;
      else if (r && r->sym->type == STT_SECTION) {
        if (const Fn* t = fn_at(fns, r->sym->shndx, imm + 1)) op.ref = t->name;
      } else if (const Fn* t = fn_at(fns, sec, slot + 1 + imm)) op.ref = t->name;
    }
  } else if (jmp && opc == 0x00) {
    op.kind = Op::Goto;
    // gotol (JMP32 class JA) carries its offset in imm.
    op.target = slot + 1 + (cls == 0x06 ? imm : off);
  } else if (jmp && (bpf_cond(opc) || opc == 0xe0)) {
    op.kind = Op::Cond;
    op.target = slot + 1 + off;
    // may_goto (BPF_JCOND) is conditional too: The verifier may take it or not.
    if (opc == 0xe0) op.text = "may_goto";
    else {
      const char w = cls == 0x06 ? 'w' : 'r';
      op.text = w + std::to_string(dst) + " " + bpf_cond(opc) + " " +
                ((code & 0x08) ? w + std::to_string(src) : std::to_string(imm));
    }
  }
  return op;
}

bool bpf_decl_map(const Image& im, const Sym& y) { return y.type == STT_OBJECT && is_maps_sec(im, y.shndx); }

// aarch64: Four-byte instructions; only those that touch control flow decode.
long sext(uint32_t v, int bits) { return (long)((int64_t)((uint64_t)v << (64 - bits)) >> (64 - bits)); }

Op a64_decode(const Image& im, size_t sec, long slot, const std::vector<Fn>& fns) {
  static const char* cc[] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                             "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
  Op op;
  const Sec& s = im.secs[sec];
  uint32_t w;
  if (!at(im.img, s.off + (uint64_t)slot * 4, w)) return op;
  const Reloc* r = reloc_at(im, sec, (uint64_t)slot * 4);
  // The name a direct branch reaches: its relocation's symbol, or the
  // function at its target when the object is already linked.
  auto name_of = [&](long target) -> std::string {
    if (r && (r->type == R_AARCH64_CALL26 || r->type == R_AARCH64_JUMP26)) {
      if (r->sym->type != STT_SECTION) return r->sym->name;
      if (const Fn* t = fn_at(fns, r->sym->shndx, (long)(r->addend / 4))) return t->name;
      return {};
    }
    if (const Fn* t = fn_at(fns, sec, target)) return t->name;
    return {};
  };
  const char reg = (w >> 31) ? 'x' : 'w';
  if ((w & 0xfc000000) == 0x14000000) {                 // b
    op.kind = Op::Goto;
    op.target = r ? -1 : slot + sext(w & 0x3ffffff, 26);
    op.ref = name_of(op.target);
  } else if ((w & 0xfc000000) == 0x94000000) {          // bl
    op.kind = Op::Call;
    op.ref = name_of(slot + sext(w & 0x3ffffff, 26));
  } else if ((w & 0xff000010) == 0x54000000) {          // b.cond
    op.kind = Op::Cond;
    op.target = slot + sext((w >> 5) & 0x7ffff, 19);
    op.text = cc[w & 0xf];
  } else if ((w & 0x7e000000) == 0x34000000) {          // cbz, cbnz
    op.kind = Op::Cond;
    op.target = slot + sext((w >> 5) & 0x7ffff, 19);
    op.text = reg + std::to_string(w & 0x1f) + ((w >> 24) & 1 ? " != 0" : " == 0");
  } else if ((w & 0x7e000000) == 0x36000000) {          // tbz, tbnz
    op.kind = Op::Cond;
    op.target = slot + sext((w >> 5) & 0x3fff, 14);
    op.text = "bit " + std::to_string(((w >> 31) << 5) | ((w >> 19) & 0x1f)) + " of " + reg +
              std::to_string(w & 0x1f) + ((w >> 24) & 1 ? " != 0" : " == 0");
  } else if ((w & 0xfffffc1f) == 0xd65f0000 || (w & 0xfffffbff) == 0xd65f0bff) {   // ret, retaa, retab
    op.kind = Op::Return;
  } else if ((w & 0xfffffc1f) == 0xd61f0000) {          // br
    op.kind = Op::Indirect;
  }
  return op;
}

// x86-64: One slot is one byte, so a block's line is a byte offset. Nothing
// says where an instruction ends but the instruction itself, so this decodes
// every one: Legacy prefixes, REX and REX2, VEX and EVEX, the one-, two- and
// three-byte opcode maps, ModRM, SIB, displacement and immediate. Only the
// control flow is named; everything else is a length.
const char* x86_cc[] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                        "s", "ns", "p", "np", "l", "ge", "le", "g"};

// ModRM and what follows it (SIB, displacement), from p[i]; the index past it.
size_t x86_modrm(const uint8_t* p, size_t i, size_t avail, int* reg) {
  if (i >= avail) return avail;
  const uint8_t m = p[i++];
  const int mod = m >> 6, rm = m & 7;
  if (reg) *reg = (m >> 3) & 7;
  if (mod != 3) {
    if (rm == 4) {
      if (i >= avail) return avail;
      const uint8_t sib = p[i++];
      if (mod == 0 && (sib & 7) == 5) i += 4;
    } else if (mod == 0 && rm == 5) {
      i += 4;   // RIP-relative
    }
    if (mod == 1) i += 1;
    else if (mod == 2) i += 4;
  }
  return i;
}

Op x86_decode(const Image& im, size_t sec, long slot, const std::vector<Fn>& fns) {
  Op op;
  const Sec& s = im.secs[sec];
  const uint64_t base = s.off + (uint64_t)slot;
  if (base >= im.img.size() || (uint64_t)slot >= s.size) return op;
  const size_t avail = (size_t)std::min<uint64_t>({s.size - (uint64_t)slot, im.img.size() - base, 15});
  const uint8_t* p = reinterpret_cast<const uint8_t*>(im.img.data() + base);
  size_t i = 0;
  bool opsz16 = false, addr32 = false, rexw = false;
  for (; i < avail; ++i) {
    const uint8_t b = p[i];
    if (b == 0x66) opsz16 = true;
    else if (b == 0x67) addr32 = true;
    else if (!(b == 0xf0 || b == 0xf2 || b == 0xf3 || b == 0x2e || b == 0x36 || b == 0x3e ||
               b == 0x26 || b == 0x64 || b == 0x65)) break;
  }
  int map = 0;
  bool vex = false;
  if (i < avail && (p[i] & 0xf0) == 0x40) { rexw = p[i] & 8; ++i; }
  else if (i + 1 < avail && p[i] == 0xd5) { rexw = p[i + 1] & 8; map = (p[i + 1] & 0x80) ? 1 : 0; i += 2; }
  if (i >= avail) { op.width = (int)avail; return op; }
  uint8_t opc = p[i];
  if (opc == 0xc5 && i + 2 < avail) {                       // two-byte VEX
    map = 1; vex = true; opc = p[i + 2]; i += 3;
  } else if (opc == 0xc4 && i + 3 < avail) {                // three-byte VEX
    map = p[i + 1] & 0x1f; rexw = p[i + 2] & 0x80; vex = true; opc = p[i + 3]; i += 4;
  } else if (opc == 0x62 && i + 4 < avail) {                // EVEX
    map = p[i + 1] & 0x07; rexw = p[i + 2] & 0x80; vex = true; opc = p[i + 4]; i += 5;
  } else if (map == 0 && opc == 0x0f && i + 1 < avail) {
    if (p[i + 1] == 0x38 && i + 2 < avail) { map = 2; opc = p[i + 2]; i += 3; }
    else if (p[i + 1] == 0x3a && i + 2 < avail) { map = 3; opc = p[i + 2]; i += 3; }
    else { map = 1; opc = p[i + 1]; i += 2; }
  } else {
    ++i;
  }
  const size_t immz = opsz16 && !rexw ? 2 : 4;
  bool modrm = false;
  size_t imm = 0;
  int reg = -1;
  if (vex) {
    modrm = !(map == 1 && opc == 0x77);                     // vzeroupper, vzeroall
    if (map == 3 || (map == 1 && ((opc >= 0x70 && opc <= 0x73) || opc == 0xc2 || (opc >= 0xc4 && opc <= 0xc6))))
      imm = 1;
  } else if (map == 0) {
    if (opc < 0x40) {
      const int lo = opc & 7;
      if (lo <= 3) modrm = true;
      else if (lo == 4) imm = 1;
      else if (lo == 5) imm = immz;
    } else if (opc == 0x63 || (opc >= 0x84 && opc <= 0x8f) || (opc >= 0xd0 && opc <= 0xd3) ||
               (opc >= 0xd8 && opc <= 0xdf) || opc == 0xfe || opc == 0xff) {
      modrm = true;
    } else if (opc == 0x68) imm = immz;
    else if (opc == 0x69) { modrm = true; imm = immz; }
    else if (opc == 0x6a || (opc >= 0x70 && opc <= 0x7f) || opc == 0xa8 || (opc >= 0xb0 && opc <= 0xb7) ||
             opc == 0xcd || (opc >= 0xe0 && opc <= 0xe7) || opc == 0xeb) imm = 1;
    else if (opc == 0x6b || opc == 0x80 || opc == 0x83 || opc == 0xc0 || opc == 0xc1 || opc == 0xc6) { modrm = true; imm = 1; }
    else if (opc == 0x81 || opc == 0xc7) { modrm = true; imm = immz; }
    else if (opc >= 0xa0 && opc <= 0xa3) imm = addr32 ? 4 : 8;
    else if (opc == 0xa9) imm = immz;
    else if (opc >= 0xb8 && opc <= 0xbf) imm = rexw ? 8 : immz;
    else if (opc == 0xc2 || opc == 0xca) imm = 2;
    else if (opc == 0xc8) imm = 3;
    else if (opc == 0xe8 || opc == 0xe9) imm = 4;
    else if (opc == 0xf6 || opc == 0xf7) modrm = true;      // test's immediate depends on reg
  } else if (map == 1) {
    if ((opc >= 0x80 && opc <= 0x8f)) imm = 4;
    else if ((opc >= 0x70 && opc <= 0x73) || opc == 0xa4 || opc == 0xac || opc == 0xba || opc == 0xc2 ||
             (opc >= 0xc4 && opc <= 0xc6) || opc == 0x0f) { modrm = true; imm = 1; }
    else if (opc <= 0x03 || opc == 0x0d || (opc >= 0x10 && opc <= 0x23) || (opc >= 0x28 && opc <= 0x2f) ||
             (opc >= 0x40 && opc <= 0x76) || (opc >= 0x78 && opc <= 0x7f) || (opc >= 0x90 && opc <= 0x9f) ||
             opc == 0xa3 || opc == 0xa5 || (opc >= 0xab && opc <= 0xaf && opc != 0xac) ||
             (opc >= 0xb0 && opc <= 0xbf && opc != 0xba) || opc == 0xc0 || opc == 0xc1 || opc == 0xc3 ||
             opc == 0xc7 || opc >= 0xd0)
      modrm = true;
  } else if (map == 2) {
    modrm = true;
  } else if (map == 3) {
    modrm = true; imm = 1;
  }
  if (modrm) i = x86_modrm(p, i, avail, &reg);
  if (!vex && map == 0 && (opc == 0xf6 || opc == 0xf7) && (reg == 0 || reg == 1)) imm = opc == 0xf6 ? 1 : immz;
  i += imm;
  op.width = (int)std::min(i, avail);
  if (op.width < 1) op.width = 1;
  const long next = slot + op.width;

  // Control flow.
  auto rel = [&](size_t n) -> long {
    if ((size_t)op.width < n) return 0;
    if (n == 1) return (int8_t)p[op.width - 1];
    int32_t v;
    std::memcpy(&v, p + op.width - 4, 4);
    return v;
  };
  // A rel32 branch's relocation sits on its last four bytes: The named target
  // of a call or tail call into another function or another object.
  const Reloc* r = reloc_at(im, sec, (uint64_t)next - 4);
  auto name_of = [&](long target) -> std::string {
    if (r && (r->type == R_X86_64_PC32 || r->type == R_X86_64_PLT32)) {
      if (r->sym->type != STT_SECTION) return r->sym->name;
      if (const Fn* t = fn_at(fns, r->sym->shndx, (long)(r->addend + 4))) return t->name;
      return {};
    }
    if (const Fn* t = fn_at(fns, sec, target)) return t->name;
    return {};
  };
  if (vex) return op;
  if (map == 0) {
    if (opc >= 0x70 && opc <= 0x7f) { op.kind = Op::Cond; op.target = next + rel(1); op.text = x86_cc[opc & 15]; }
    else if (opc >= 0xe0 && opc <= 0xe3) {
      static const char* lp[] = {"loopne", "loope", "loop", "jrcxz"};
      op.kind = Op::Cond; op.target = next + rel(1); op.text = lp[opc - 0xe0];
    } else if (opc == 0xeb) { op.kind = Op::Goto; op.target = next + rel(1); op.ref = name_of(op.target); }
    else if (opc == 0xe9) {
      op.kind = Op::Goto;
      op.target = r ? -1 : next + rel(4);
      op.ref = name_of(op.target);
    } else if (opc == 0xe8) { op.kind = Op::Call; op.ref = name_of(next + rel(4)); }
    else if (opc == 0xff && (reg == 2 || reg == 3)) op.kind = Op::Call;
    else if (opc == 0xff && (reg == 4 || reg == 5)) op.kind = Op::Indirect;
    else if (opc == 0xc2 || opc == 0xc3 || opc == 0xca || opc == 0xcb || opc == 0xcf || opc == 0xf4)
      op.kind = Op::Return;
  } else if (map == 1) {
    if (opc >= 0x80 && opc <= 0x8f) { op.kind = Op::Cond; op.target = next + rel(4); op.text = x86_cc[opc & 15]; }
    else if (opc == 0x0b || opc == 0x07 || opc == 0x35) op.kind = Op::Return;   // ud2, sysret, sysexit
  }
  return op;
}

const Machine kBpf{"bpf", 8, bpf_decl_map, bpf_decode};
const Machine kA64{"aarch64", 4, nullptr, a64_decode};
const Machine kX86{"x86-64", 1, nullptr, x86_decode};

// aarch64 marks literal pools and jump tables inside code with $d mapping
// symbols and code with $x: The data words are not instructions.
std::vector<std::pair<long, long>> data_ranges(const Image& im, size_t sec, int slot_bytes, long nslots) {
  std::vector<std::pair<long, char>> marks;
  for (const Sym& y : im.syms) {
    if (y.shndx != sec || y.name.size() < 2 || y.name[0] != '$') continue;
    if ((y.name[1] == 'd' || y.name[1] == 'x') && (y.name.size() == 2 || y.name[2] == '.'))
      marks.push_back({(long)(y.value / (uint64_t)slot_bytes), y.name[1]});
  }
  sublimation_order_u64(marks, false, [](const std::pair<long, char>& m) { return (uint64_t)m.first; });
  std::vector<std::pair<long, long>> out;
  for (size_t k = 0; k < marks.size(); ++k)
    if (marks[k].second == 'd')
      out.push_back({marks[k].first, k + 1 < marks.size() ? marks[k + 1].first : nslots});
  return out;
}

}  // namespace

ObjectKind static_object_kind(const std::string& path) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) return ObjectKind::NotElf;
  Elf64_Ehdr eh{};
  const size_t n = std::fread(&eh, 1, sizeof eh, f);
  std::fclose(f);
  if (n < EI_NIDENT || std::memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) return ObjectKind::NotElf;
  if (n != sizeof eh || eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB)
    return ObjectKind::OtherElf;
  if (eh.e_machine == EM_BPF) return ObjectKind::Bpf;
  if (eh.e_machine == EM_AARCH64) return ObjectKind::Aarch64;
  if (eh.e_machine == EM_X86_64) return ObjectKind::X86_64;
  return ObjectKind::OtherElf;
}

const char* static_object_dialect(ObjectKind k) {
  return k == ObjectKind::Bpf ? kBpf.dialect : k == ObjectKind::Aarch64 ? kA64.dialect
       : k == ObjectKind::X86_64 ? kX86.dialect : "?";
}

bool static_scan_object(const std::string& path, size_t file_idx, std::string& body,
                        StaticObjectCounts& counts, std::string& err) {
  const ObjectKind kind = static_object_kind(path);
  const Machine* m = kind == ObjectKind::Bpf ? &kBpf : kind == ObjectKind::Aarch64 ? &kA64
                   : kind == ObjectKind::X86_64 ? &kX86 : nullptr;
  if (!m) { err = "not an object this lane reads"; return false; }
  Image im;
  if (!load(path, im, err)) return false;
  const bool linked = im.eh.e_type != ET_REL;
  auto exec_sec = [&](uint16_t k) {
    return k < im.secs.size() && im.secs[k].type == SHT_PROGBITS && (im.secs[k].flags & SHF_EXECINSTR);
  };
  std::vector<Fn> fns;
  for (const Sym& y : im.syms) {
    if (y.type != STT_FUNC || !exec_sec(y.shndx)) continue;
    const Sec& s = im.secs[y.shndx];
    // A linked object's symbol values are addresses, a relocatable one's offsets.
    const uint64_t off = linked ? y.value - s.addr : y.value;
    const long n = (long)(s.size / (uint64_t)m->slot_bytes);
    const long start = (long)(off / (uint64_t)m->slot_bytes);
    const long end = y.size ? start + (long)(y.size / (uint64_t)m->slot_bytes) : n;
    if (start < 0 || start >= n || fn_at(fns, y.shndx, start)) continue;
    // ENTERED FROM OUTSIDE THE OBJECT: in a relocatable object, anything
    // global or weak, which another object may call (a BPF program is one,
    // found by its loader); in a linked one, what .dynsym exports and the
    // function at the entry point.
    const bool entered = linked ? im.dyn_exports.count(y.name) || y.value == im.eh.e_entry
                                : y.bind == STB_GLOBAL || y.bind == STB_WEAK;
    fns.push_back({y.shndx, start, std::min(end, n), y.name, entered});
  }
  sublimation_order_u64(fns, false, [](const Fn& f) {
    return ((uint64_t)f.sec << 32) | (uint64_t)(uint32_t)f.start;
  });
  // A symbol with no size runs to the next function in its section.
  for (size_t k = 0; k + 1 < fns.size(); ++k)
    if (fns[k].sec == fns[k + 1].sec && fns[k].end > fns[k + 1].start) fns[k].end = fns[k + 1].start;

  const std::string fs = std::to_string(file_idx);
  body += "file " + fs + " " + m->dialect + " " + path + "\n";
  for (const Fn& f : fns) {
    body += "D\t" + fs + "\t" + std::to_string(f.start) + "\tfunction\t" + f.name + "\n";
    ++counts.decls;
  }
  for (const Fn& f : fns) {
    if (!f.entered) continue;
    body += "R\t" + fs + "\t" + std::to_string(f.start) + "\t<file>\t" + f.name + "\n";
    ++counts.refs;
  }
  if (m->decls_map)
    for (const Sym& y : im.syms) {
      if (!m->decls_map(im, y)) continue;
      body += "D\t" + fs + "\t0\tmap\t" + y.name + "\n";
      ++counts.decls;
    }

  for (size_t fk = 0; fk < fns.size(); ++fk) {
    const Fn& f = fns[fk];
    const long nslots = (long)(im.secs[f.sec].size / (uint64_t)m->slot_bytes);
    const auto data = data_ranges(im, f.sec, m->slot_bytes, nslots);
    auto is_data = [&](long pc) {
      for (const auto& d : data) if (pc >= d.first && pc < d.second) return true;
      return false;
    };
    std::map<long, Op> ops;
    for (long pc = f.start; pc < f.end;) {
      Op op = is_data(pc) ? Op{} : m->decode(im, f.sec, pc, fns);
      const long w = op.width;
      ops.emplace(pc, std::move(op));
      pc += w;
    }
    auto inside = [&](long t) { return t >= f.start && t < f.end && ops.count(t); };
    std::set<long> leaders{f.start};
    for (const auto& [pc, op] : ops) {
      const long next = pc + op.width;
      if (op.kind == Op::Cond || op.kind == Op::Goto) {
        if (inside(op.target)) leaders.insert(op.target);
        if (next < f.end) leaders.insert(next);
      } else if ((op.kind == Op::Return || op.kind == Op::Indirect) && next < f.end) {
        leaders.insert(next);
      }
    }
    std::vector<long> first(leaders.begin(), leaders.end());
    std::map<long, size_t> block_of;
    for (size_t b = 0; b < first.size(); ++b) block_of[first[b]] = b + 2;

    struct E { size_t from, to; const char* kind; };
    std::vector<E> edges{{0, 2, "fall"}};
    std::vector<std::string> kinds(first.size()), texts(first.size());
    std::vector<long> last(first.size());
    for (size_t b = 0; b < first.size(); ++b) {
      const long lim = b + 1 < first.size() ? first[b + 1] : f.end;
      long term = first[b];
      for (auto it = ops.find(first[b]); it != ops.end() && it->first < lim; ++it) term = it->first;
      last[b] = term;
      const Op& op = ops.at(term);
      const size_t self = b + 2;
      const bool has_next = b + 1 < first.size();
      kinds[b] = "stmt";
      if (op.kind == Op::Cond) {
        kinds[b] = "cond";
        texts[b] = op.text;
        if (block_of.count(op.target)) edges.push_back({self, block_of[op.target], "true"});
        else edges.push_back({self, 1, "goto-unresolved"});
        if (has_next) edges.push_back({self, self + 1, "false"});
      } else if (op.kind == Op::Goto) {
        // A goto out of the function to a named function is a tail call: It
        // leaves, as a return does. Anywhere else unnamed is unresolved.
        if (block_of.count(op.target)) edges.push_back({self, block_of[op.target], "goto"});
        else edges.push_back({self, 1, op.ref.empty() ? "goto-unresolved" : "return"});
      } else if (op.kind == Op::Return) {
        edges.push_back({self, 1, "return"});
      } else if (op.kind == Op::Indirect) {
        edges.push_back({self, 1, "goto-unresolved"});
      } else if (has_next) {
        edges.push_back({self, self + 1, "fall"});
      }
    }

    // Guard depth: the conditional blocks that dominate this one, from
    // Cooper, Harvey and Kennedy's iteration over reverse postorder.
    const size_t nb = first.size() + 2;
    std::vector<std::vector<size_t>> succ(nb), pred(nb);
    for (const E& e : edges) { succ[e.from].push_back(e.to); pred[e.to].push_back(e.from); }
    std::vector<size_t> post, stack_v{0}, stack_k{0};
    std::vector<uint8_t> seen(nb, 0);
    seen[0] = 1;
    while (!stack_v.empty()) {
      const size_t x = stack_v.back();
      if (stack_k.back() < succ[x].size()) {
        const size_t y = succ[x][stack_k.back()++];
        if (!seen[y]) { seen[y] = 1; stack_v.push_back(y); stack_k.push_back(0); }
      } else { post.push_back(x); stack_v.pop_back(); stack_k.pop_back(); }
    }
    std::vector<size_t> rpo(nb, 0);
    for (size_t k = 0; k < post.size(); ++k) rpo[post[k]] = post.size() - 1 - k;
    std::vector<long> idom(nb, -1);
    idom[0] = 0;
    for (bool changed = true; changed;) {
      changed = false;
      for (size_t k = post.size(); k-- > 0;) {
        const size_t x = post[k];
        if (x == 0) continue;
        long nd = -1;
        for (size_t p : pred[x]) {
          if (idom[p] < 0) continue;
          if (nd < 0) { nd = (long)p; continue; }
          long a = (long)p, c = nd;
          while (a != c) {
            while (rpo[a] > rpo[c]) a = idom[a];
            while (rpo[c] > rpo[a]) c = idom[c];
          }
          nd = a;
        }
        if (nd != idom[x]) { idom[x] = nd; changed = true; }
      }
    }
    for (size_t b = 0; b < first.size(); ++b) {
      if (kinds[b] != "cond") continue;
      int depth = 0;
      for (long x = idom[b + 2]; x > 0 && x != idom[x]; x = idom[x])
        if ((size_t)x >= 2 && kinds[(size_t)x - 2] == "cond") ++depth;
      body += "G\t" + fs + "\t" + std::to_string(last[b]) + "\t" + std::to_string(depth) +
              "\tjump\t" + f.name + "\t" + texts[b] + "\n";
      ++counts.guards;
    }
    for (const auto& [pc, op] : ops) {
      if (op.ref.empty()) continue;
      body += "R\t" + fs + "\t" + std::to_string(pc) + "\t" + f.name + "\t" + op.ref + "\n";
      ++counts.refs;
    }

    const std::string head = fs + "\t" + std::to_string(fk) + "\t" + f.name + "\t";
    body += "B\t" + head + "0\tentry\t" + std::to_string(f.start) + "\t" + std::to_string(f.start) + "\t\n";
    body += "B\t" + head + "1\texit\t" + std::to_string(f.end - 1) + "\t" + std::to_string(f.end - 1) + "\t\n";
    for (size_t b = 0; b < first.size(); ++b)
      body += "B\t" + head + std::to_string(b + 2) + "\t" + kinds[b] + "\t" + std::to_string(first[b]) +
              "\t" + std::to_string(last[b]) + "\t" + texts[b] + "\n";
    for (const E& e : edges)
      body += "E\t" + head + std::to_string(e.from) + "\t" + std::to_string(e.to) + "\t" + e.kind + "\n";
    counts.blocks += nb;
    counts.edges += edges.size();
  }
  return true;
}
