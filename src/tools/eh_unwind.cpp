// The call frame information walk. .eh_frame carries DWARF call frame
// information (DWARF 4 section 6.4, in the pointer encodings of the Linux
// Standard Base's .eh_frame): For each range of code an FDE holds a program
// that says how to compute the canonical frame address (CFA) and where each
// register was saved. Run to a frame's pc, it names the slot of the frame's
// return address, which the copied stack holds, and that is the caller's pc.
// It reaches through code built without frame pointers, where a frame-pointer
// walk stops, because the compiler emits the information for every function
// whether or not it keeps a frame pointer.
#include "eh_unwind.hpp"

#include <elf.h>
#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

// After the std headers: c23_compat.h's C23 unreachable() macro must not
// precede the libstdc++ headers.
#include "sublimation_order.hpp"

namespace montauk::unwind {
namespace {

// DWARF's x86-64 register numbers: 0..15 the general registers, 16 the
// return address. Vector and x87 columns are not tracked.
constexpr int kRegs = 17;
constexpr int kRbp = 6, kRsp = 7, kRip = 16;

using Regs = std::array<std::optional<uint64_t>, kRegs>;

struct Reader {
  const uint8_t* base;
  size_t pos, end;
  bool bad = false;

  uint8_t u8() {
    if (pos >= end) { bad = true; return 0; }
    return base[pos++];
  }
  template <class T> T fixed() {
    T v{};
    if (end - pos < sizeof(T) || pos > end) { bad = true; return v; }
    std::memcpy(&v, base + pos, sizeof(T));
    pos += sizeof(T);
    return v;
  }
  uint64_t uleb() {
    uint64_t v = 0;
    for (int shift = 0;; shift += 7) {
      const uint8_t b = u8();
      if (bad) return 0;
      if (shift < 64) v |= uint64_t(b & 0x7f) << shift;
      if (!(b & 0x80)) return v;
    }
  }
  int64_t sleb() {
    int64_t v = 0;
    int shift = 0;
    uint8_t b;
    do {
      b = u8();
      if (bad) return 0;
      if (shift < 64) v |= int64_t(b & 0x7f) << shift;
      shift += 7;
    } while (b & 0x80);
    if (shift < 64 && (b & 0x40)) v |= -(int64_t(1) << shift);
    return v;
  }
  // A pointer in DW_EH_PE encoding enc, read from the field at vaddr base_vaddr + pos.
  std::optional<uint64_t> encoded(uint8_t enc, uint64_t base_vaddr) {
    if (enc == 0xff) return std::nullopt;  // DW_EH_PE_omit
    const uint64_t field = base_vaddr + pos;
    uint64_t v;
    switch (enc & 0x0f) {
      case 0x00: v = fixed<uint64_t>(); break;  // absptr
      case 0x01: v = uleb(); break;
      case 0x02: v = fixed<uint16_t>(); break;
      case 0x03: v = fixed<uint32_t>(); break;
      case 0x04: v = fixed<uint64_t>(); break;
      case 0x09: v = static_cast<uint64_t>(sleb()); break;
      case 0x0a: v = static_cast<uint64_t>(static_cast<int64_t>(fixed<int16_t>())); break;
      case 0x0b: v = static_cast<uint64_t>(static_cast<int64_t>(fixed<int32_t>())); break;
      case 0x0c: v = fixed<uint64_t>(); break;
      default: bad = true; return std::nullopt;
    }
    if (bad) return std::nullopt;
    switch (enc & 0x70) {
      case 0x00: return v;
      case 0x10: return v + field;  // pcrel
      default: return std::nullopt;  // textrel, datarel, funcrel: not what .eh_frame uses on x86-64
    }
  }
};

struct Cie {
  uint64_t code_align = 1;
  int64_t data_align = 0;
  uint32_t ra = kRip;
  uint8_t fde_enc = 0;
  bool aug_z = false, signal = false;
  size_t insn = 0, end = 0;
};

struct Fde { uint64_t lo, hi; size_t cie, insn, end; };

struct Elf {
  std::string img;
  struct Load { uint64_t off, vaddr, filesz; };
  std::vector<Load> loads;
  size_t eh_off = 0, eh_size = 0;
  uint64_t eh_vaddr = 0;
  std::unordered_map<size_t, Cie> cies;
  std::vector<Fde> fdes;  // by lo
  const uint8_t* eh() const { return reinterpret_cast<const uint8_t*>(img.data()) + eh_off; }
};

// The entry header at `at`: Its body's start and end, and whether the id field is 8 bytes.
bool entry(const Elf& e, size_t at, size_t& body, size_t& end, bool& wide) {
  Reader r{e.eh(), at, e.eh_size};
  uint64_t len = r.fixed<uint32_t>();
  wide = len == 0xffffffff;
  if (wide) len = r.fixed<uint64_t>();
  if (r.bad || len == 0 || len > e.eh_size - r.pos) return false;
  body = r.pos;
  end = r.pos + len;
  return true;
}

bool parse_cie(const Elf& e, size_t at, Cie& c) {
  size_t body, end;
  bool wide;
  if (!entry(e, at, body, end, wide)) return false;
  Reader r{e.eh(), body, end};
  const uint64_t id = wide ? r.fixed<uint64_t>() : r.fixed<uint32_t>();
  if (r.bad || id != 0) return false;
  const uint8_t version = r.u8();
  std::string aug;
  for (uint8_t ch = r.u8(); ch != 0 && !r.bad; ch = r.u8()) aug += static_cast<char>(ch);
  if (r.bad || (version != 1 && version != 3 && version != 4)) return false;
  if (version == 4) { r.u8(); r.u8(); }  // address and segment selector sizes
  if (aug.find("eh") != std::string::npos) r.fixed<uint64_t>();
  c.code_align = r.uleb();
  c.data_align = r.sleb();
  c.ra = version == 1 ? r.u8() : static_cast<uint32_t>(r.uleb());
  if (!aug.empty() && aug[0] == 'z') {
    c.aug_z = true;
    const uint64_t alen = r.uleb();
    if (r.bad || alen > end - r.pos) return false;
    const size_t aend = r.pos + alen;
    for (size_t i = 1; i < aug.size() && !r.bad; ++i) {
      if (aug[i] == 'R') c.fde_enc = r.u8();
      else if (aug[i] == 'L') r.u8();
      else if (aug[i] == 'P') r.encoded(r.u8() & 0x0f, 0);
      else if (aug[i] == 'S') c.signal = true;
      else break;  // the rest of the augmentation data is skipped by its length
    }
    r.pos = aend;
  } else if (!aug.empty() && aug != "eh") {
    return false;  // an augmentation with no length cannot be stepped over
  }
  if (r.bad) return false;
  c.insn = r.pos;
  c.end = end;
  return true;
}

void index_fdes(Elf& e) {
  size_t at = 0;
  while (e.eh_size - at >= 4) {
    size_t body, end;
    bool wide;
    if (!entry(e, at, body, end, wide)) break;
    Reader r{e.eh(), body, end};
    const uint64_t id = wide ? r.fixed<uint64_t>() : r.fixed<uint32_t>();
    if (!r.bad && id != 0 && id <= body) {
      const size_t cie_at = body - id;  // the CIE pointer counts back from its own field
      auto it = e.cies.find(cie_at);
      if (it == e.cies.end()) {
        Cie c;
        if (parse_cie(e, cie_at, c)) it = e.cies.emplace(cie_at, c).first;
      }
      if (it != e.cies.end()) {
        const Cie& c = it->second;
        const auto lo = r.encoded(c.fde_enc, e.eh_vaddr);
        const auto range = r.encoded(c.fde_enc & 0x0f, 0);
        if (lo && range && *range && !r.bad) {
          if (c.aug_z) r.pos += r.uleb();
          if (!r.bad && r.pos <= end) e.fdes.push_back({*lo, *lo + *range, cie_at, r.pos, end});
        }
      }
    }
    at = end;
  }
  sublimation_order_u64(e.fdes, false, [](const Fde& f) { return f.lo; });
}

template <class T> bool at_off(const std::string& img, uint64_t off, T& out) {
  if (off > img.size() || img.size() - off < sizeof(T)) return false;
  std::memcpy(&out, img.data() + off, sizeof(T));
  return true;
}

std::unique_ptr<Elf> load(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return nullptr;
  auto e = std::make_unique<Elf>();
  e->img.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  const std::string& img = e->img;
  Elf64_Ehdr eh{};
  if (!at_off(img, 0, eh) || std::memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_machine != EM_X86_64)
    return nullptr;
  Elf64_Phdr hdr_ph{};
  bool have_hdr = false;
  for (uint16_t i = 0; i < eh.e_phnum; ++i) {
    Elf64_Phdr ph{};
    if (!at_off(img, eh.e_phoff + uint64_t(i) * eh.e_phentsize, ph)) break;
    if (ph.p_type == PT_LOAD) e->loads.push_back({ph.p_offset, ph.p_vaddr, ph.p_filesz});
    if (ph.p_type == PT_GNU_EH_FRAME) { hdr_ph = ph; have_hdr = true; }
  }
  Elf64_Shdr strtab{};
  if (eh.e_shoff && eh.e_shstrndx < eh.e_shnum &&
      at_off(img, eh.e_shoff + uint64_t(eh.e_shstrndx) * eh.e_shentsize, strtab)) {
    for (uint16_t i = 0; i < eh.e_shnum; ++i) {
      Elf64_Shdr sh{};
      if (!at_off(img, eh.e_shoff + uint64_t(i) * eh.e_shentsize, sh)) break;
      const uint64_t name = strtab.sh_offset + sh.sh_name;
      if (sh.sh_type == SHT_NOBITS || name >= img.size()) continue;
      if (std::strncmp(img.data() + name, ".eh_frame", img.size() - name) == 0 &&
          sh.sh_offset <= img.size() && sh.sh_size <= img.size() - sh.sh_offset) {
        e->eh_off = sh.sh_offset;
        e->eh_size = sh.sh_size;
        e->eh_vaddr = sh.sh_addr;
        break;
      }
    }
  }
  // No section headers: .eh_frame_hdr names where .eh_frame starts, and the
  // load segment holding it bounds how far it can run.
  if (!e->eh_size && have_hdr) {
    Reader r{reinterpret_cast<const uint8_t*>(img.data()), hdr_ph.p_offset, img.size()};
    const uint8_t version = r.u8(), ptr_enc = r.u8();
    r.u8();
    r.u8();
    const auto eh_vaddr = r.encoded(ptr_enc, hdr_ph.p_vaddr - hdr_ph.p_offset);
    if (!r.bad && version == 1 && eh_vaddr)
      for (const auto& l : e->loads)
        if (*eh_vaddr >= l.vaddr && *eh_vaddr - l.vaddr < l.filesz) {
          e->eh_vaddr = *eh_vaddr;
          e->eh_off = l.off + (*eh_vaddr - l.vaddr);
          e->eh_size = l.filesz - (*eh_vaddr - l.vaddr);
          break;
        }
  }
  if (!e->eh_size || e->eh_off > img.size() || e->eh_size > img.size() - e->eh_off) return nullptr;
  index_fdes(*e);
  return e;
}

// Each file once, and only while it is still the inode the capture mapped: A
// file rebuilt since the capture would unwind by rules the code never ran.
const Elf* elf_for(const Segment& s) {
  static std::mutex mu;
  static std::unordered_map<std::string, std::unique_ptr<Elf>> cache;
  std::lock_guard lk(mu);
  const std::string key = s.path + '\0' + std::to_string(s.inode);
  auto it = cache.find(key);
  if (it == cache.end()) {
    struct stat st{};
    std::unique_ptr<Elf> e;
    if (::stat(s.path.c_str(), &st) == 0 && (s.inode == 0 || st.st_ino == s.inode)) e = load(s.path);
    it = cache.emplace(key, std::move(e)).first;
  }
  return it->second.get();
}

const Fde* find_fde(const Elf& e, uint64_t pc) {
  auto it = std::upper_bound(e.fdes.begin(), e.fdes.end(), pc,
                             [](uint64_t v, const Fde& f) { return v < f.lo; });
  if (it == e.fdes.begin()) return nullptr;
  --it;
  return pc < it->hi ? &*it : nullptr;
}

enum class Kind : uint8_t { Unspec, Undef, Same, Off, ValOff, Reg, Expr, ValExpr };
struct Rule { Kind k = Kind::Unspec; int64_t v = 0; size_t e = 0, elen = 0; };
struct Row {
  int cfa_reg = -1;
  int64_t cfa_off = 0;
  bool cfa_expr = false;
  size_t ce = 0, celen = 0;
  std::array<Rule, kRegs> r{};
};

// Runs the instructions in [p, end) from location loc, stopping before the
// first advance past pc, and leaves the rules in force at pc in row.
bool run(const Elf& e, const Cie& c, size_t p, size_t end, uint64_t loc, uint64_t pc, Row& row,
         const Row* initial) {
  Reader r{e.eh(), p, end};
  std::vector<Row> saved;
  auto set = [&](uint64_t reg, Rule u) { if (reg < kRegs) row.r[reg] = u; };
  auto restore = [&](uint64_t reg) { if (reg < kRegs) row.r[reg] = initial ? initial->r[reg] : Rule{}; };
  while (r.pos < r.end) {
    const uint8_t op = r.u8();
    const uint8_t low = op & 0x3f;
    switch (op & 0xc0) {
      case 0x40: loc += low * c.code_align; if (loc > pc) return true; continue;
      case 0x80: set(low, {Kind::Off, int64_t(r.uleb()) * c.data_align}); continue;
      case 0xc0: restore(low); continue;
      default: break;
    }
    switch (op) {
      case 0x00: break;
      case 0x01: {
        const auto a = r.encoded(c.fde_enc, e.eh_vaddr);
        if (!a) return false;
        loc = *a;
        if (loc > pc) return true;
        break;
      }
      case 0x02: loc += r.u8() * c.code_align; if (loc > pc) return true; break;
      case 0x03: loc += r.fixed<uint16_t>() * c.code_align; if (loc > pc) return true; break;
      case 0x04: loc += r.fixed<uint32_t>() * c.code_align; if (loc > pc) return true; break;
      case 0x05: { const uint64_t reg = r.uleb(); set(reg, {Kind::Off, int64_t(r.uleb()) * c.data_align}); break; }
      case 0x06: restore(r.uleb()); break;
      case 0x07: set(r.uleb(), {Kind::Undef}); break;
      case 0x08: set(r.uleb(), {Kind::Same}); break;
      case 0x09: { const uint64_t reg = r.uleb(); set(reg, {Kind::Reg, int64_t(r.uleb())}); break; }
      case 0x0a: saved.push_back(row); break;
      case 0x0b:
        if (saved.empty()) return false;
        row = saved.back();
        saved.pop_back();
        break;
      case 0x0c: row.cfa_reg = int(r.uleb()); row.cfa_off = int64_t(r.uleb()); row.cfa_expr = false; break;
      case 0x0d: row.cfa_reg = int(r.uleb()); row.cfa_expr = false; break;
      case 0x0e: row.cfa_off = int64_t(r.uleb()); break;
      case 0x0f: {
        const uint64_t n = r.uleb();
        row.cfa_expr = true;
        row.ce = r.pos;
        row.celen = n;
        r.pos += n;
        break;
      }
      case 0x10:
      case 0x16: {
        const uint64_t reg = r.uleb(), n = r.uleb();
        set(reg, {op == 0x10 ? Kind::Expr : Kind::ValExpr, 0, r.pos, n});
        r.pos += n;
        break;
      }
      case 0x11: { const uint64_t reg = r.uleb(); set(reg, {Kind::Off, r.sleb() * c.data_align}); break; }
      case 0x12: row.cfa_reg = int(r.uleb()); row.cfa_off = r.sleb() * c.data_align; row.cfa_expr = false; break;
      case 0x13: row.cfa_off = r.sleb() * c.data_align; break;
      case 0x14: { const uint64_t reg = r.uleb(); set(reg, {Kind::ValOff, int64_t(r.uleb()) * c.data_align}); break; }
      case 0x15: { const uint64_t reg = r.uleb(); set(reg, {Kind::ValOff, r.sleb() * c.data_align}); break; }
      case 0x2e: r.uleb(); break;  // GNU_args_size
      case 0x2f: { const uint64_t reg = r.uleb(); set(reg, {Kind::Off, -int64_t(r.uleb()) * c.data_align}); break; }
      default: return false;
    }
    if (r.bad || r.pos > r.end) return false;
  }
  return !r.bad;
}

using Mem = std::optional<uint64_t> (*)(const UserContext&, uint64_t);

std::optional<uint64_t> read_stack(const UserContext& ctx, uint64_t addr) {
  if (addr < ctx.sp || addr - ctx.sp > ctx.stack_len || ctx.stack_len - (addr - ctx.sp) < 8)
    return std::nullopt;
  uint64_t v;
  std::memcpy(&v, ctx.stack + (addr - ctx.sp), 8);
  return v;
}

// A DWARF expression (the stack machine of DWARF 4 section 2.5), over the
// registers known and the copied stack, with `push` on the stack first for a
// register rule's expression.
std::optional<uint64_t> eval(const Elf& e, size_t at, size_t len, const Regs& regs, const UserContext& ctx,
                             std::optional<uint64_t> push) {
  if (at > e.eh_size || len > e.eh_size - at) return std::nullopt;
  Reader r{e.eh(), at, at + len};
  std::vector<uint64_t> st;
  if (push) st.push_back(*push);
  auto pop = [&](uint64_t& v) {
    if (st.empty()) return false;
    v = st.back();
    st.pop_back();
    return true;
  };
  auto reg = [&](uint64_t n) -> std::optional<uint64_t> { return n < kRegs ? regs[n] : std::nullopt; };
  while (r.pos < r.end) {
    const uint8_t op = r.u8();
    if (op >= 0x30 && op <= 0x4f) { st.push_back(op - 0x30); continue; }  // lit0..31
    if (op >= 0x50 && op <= 0x6f) {                                        // reg0..31
      const auto v = reg(op - 0x50);
      if (!v) return std::nullopt;
      st.push_back(*v);
      continue;
    }
    if (op >= 0x70 && op <= 0x8f) {                                        // breg0..31
      const int64_t off = r.sleb();
      const auto v = reg(op - 0x70);
      if (!v) return std::nullopt;
      st.push_back(*v + static_cast<uint64_t>(off));
      continue;
    }
    uint64_t a, b;
    switch (op) {
      case 0x03: st.push_back(r.fixed<uint64_t>()); break;  // addr
      case 0x06: {                                           // deref
        if (!pop(a)) return std::nullopt;
        const auto v = read_stack(ctx, a);
        if (!v) return std::nullopt;
        st.push_back(*v);
        break;
      }
      case 0x08: st.push_back(r.u8()); break;
      case 0x09: st.push_back(static_cast<uint64_t>(int64_t(int8_t(r.u8())))); break;
      case 0x0a: st.push_back(r.fixed<uint16_t>()); break;
      case 0x0b: st.push_back(static_cast<uint64_t>(int64_t(r.fixed<int16_t>()))); break;
      case 0x0c: st.push_back(r.fixed<uint32_t>()); break;
      case 0x0d: st.push_back(static_cast<uint64_t>(int64_t(r.fixed<int32_t>()))); break;
      case 0x0e:
      case 0x0f: st.push_back(r.fixed<uint64_t>()); break;
      case 0x10: st.push_back(r.uleb()); break;
      case 0x11: st.push_back(static_cast<uint64_t>(r.sleb())); break;
      case 0x12: if (st.empty()) return std::nullopt; st.push_back(st.back()); break;   // dup
      case 0x13: if (!pop(a)) return std::nullopt; break;                               // drop
      case 0x14: if (st.size() < 2) return std::nullopt; st.push_back(st[st.size() - 2]); break;  // over
      case 0x15: {                                                                      // pick
        const uint8_t i = r.u8();
        if (i >= st.size()) return std::nullopt;
        st.push_back(st[st.size() - 1 - i]);
        break;
      }
      case 0x16: if (st.size() < 2) return std::nullopt; std::swap(st[st.size() - 1], st[st.size() - 2]); break;
      case 0x17: {                                                                      // rot
        if (st.size() < 3) return std::nullopt;
        const size_t n = st.size();
        const uint64_t top = st[n - 1];
        st[n - 1] = st[n - 2];
        st[n - 2] = st[n - 3];
        st[n - 3] = top;
        break;
      }
      case 0x19: if (st.empty()) return std::nullopt; st.back() = static_cast<uint64_t>(std::abs(int64_t(st.back()))); break;
      case 0x1f: if (st.empty()) return std::nullopt; st.back() = static_cast<uint64_t>(-int64_t(st.back())); break;
      case 0x20: if (st.empty()) return std::nullopt; st.back() = ~st.back(); break;
      case 0x23: if (!pop(a)) return std::nullopt; st.push_back(a + r.uleb()); break;  // plus_uconst
      case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x21: case 0x22: case 0x24:
      case 0x25: case 0x26: case 0x27: case 0x29: case 0x2a: case 0x2b: case 0x2c: case 0x2d: case 0x2e: {
        if (!pop(b) || !pop(a)) return std::nullopt;
        const int64_t sa = int64_t(a), sb = int64_t(b);
        uint64_t v = 0;
        switch (op) {
          case 0x1a: v = a & b; break;
          case 0x1b: if (sb == 0) return std::nullopt; v = static_cast<uint64_t>(sa / sb); break;
          case 0x1c: v = a - b; break;
          case 0x1d: if (b == 0) return std::nullopt; v = a % b; break;
          case 0x1e: v = a * b; break;
          case 0x21: v = a | b; break;
          case 0x22: v = a + b; break;
          case 0x24: v = b < 64 ? a << b : 0; break;
          case 0x25: v = b < 64 ? a >> b : 0; break;
          case 0x26: v = static_cast<uint64_t>(b < 64 ? sa >> b : (sa < 0 ? -1 : 0)); break;
          case 0x27: v = a ^ b; break;
          case 0x29: v = sa == sb; break;
          case 0x2a: v = sa >= sb; break;
          case 0x2b: v = sa > sb; break;
          case 0x2c: v = sa <= sb; break;
          case 0x2d: v = sa < sb; break;
          case 0x2e: v = sa != sb; break;
        }
        st.push_back(v);
        break;
      }
      case 0x28:                                                                        // bra
      case 0x2f: {                                                                      // skip
        const int16_t off = r.fixed<int16_t>();
        if (op == 0x28) {
          if (!pop(a)) return std::nullopt;
          if (!a) break;
        }
        const int64_t to = int64_t(r.pos) + off;
        if (to < int64_t(at) || to > int64_t(r.end)) return std::nullopt;
        r.pos = static_cast<size_t>(to);
        break;
      }
      case 0x90: { const auto v = reg(r.uleb()); if (!v) return std::nullopt; st.push_back(*v); break; }  // regx
      case 0x92: {                                                                      // bregx
        const uint64_t n = r.uleb();
        const int64_t off = r.sleb();
        const auto v = reg(n);
        if (!v) return std::nullopt;
        st.push_back(*v + static_cast<uint64_t>(off));
        break;
      }
      case 0x96: break;  // nop
      default: return std::nullopt;
    }
    if (r.bad) return std::nullopt;
  }
  if (st.empty()) return std::nullopt;
  return st.back();
}

}  // namespace

std::vector<uint64_t> walk(const UserContext& ctx, const FindSegment& find, size_t max_frames) {
  std::vector<uint64_t> out;
  if (!ctx.ip || !max_frames) return out;
  out.push_back(ctx.ip);
  Regs regs{};
  regs[kRsp] = ctx.sp;
  regs[kRbp] = ctx.bp;
  regs[kRip] = ctx.ip;
  // The innermost frame was interrupted, not called, so its pc is the
  // instruction itself; a caller's is its return address less one, which
  // lands inside the call even when the call was a function's last instruction.
  bool exact = true;
  while (out.size() < max_frames) {
    const uint64_t pc = *regs[kRip];
    const uint64_t at = exact ? pc : pc - 1;
    const Segment* s = find(at);
    if (!s || !s->exec || at < s->start || at >= s->end || s->path.empty() || s->path[0] != '/') break;
    const Elf* e = elf_for(*s);
    if (!e) break;
    const uint64_t fo = at - s->start + s->file_off;
    std::optional<uint64_t> vaddr;
    for (const auto& l : e->loads)
      if (fo >= l.off && fo - l.off < l.filesz) { vaddr = fo - l.off + l.vaddr; break; }
    if (!vaddr) break;
    const Fde* f = find_fde(*e, *vaddr);
    if (!f) break;
    const Cie& c = e->cies.at(f->cie);
    Row row;
    if (!run(*e, c, c.insn, c.end, f->lo, *vaddr, row, nullptr)) break;
    const Row initial = row;
    if (!run(*e, c, f->insn, f->end, f->lo, *vaddr, row, &initial)) break;

    std::optional<uint64_t> cfa;
    if (row.cfa_expr) cfa = eval(*e, row.ce, row.celen, regs, ctx, std::nullopt);
    else if (row.cfa_reg >= 0 && row.cfa_reg < kRegs && regs[row.cfa_reg]) cfa = *regs[row.cfa_reg] + row.cfa_off;
    if (!cfa || !regs[kRsp] || *cfa <= *regs[kRsp]) break;  // a frame that does not move up the stack ends the walk

    Regs next = regs;
    next[kRsp] = *cfa;
    for (int i = 0; i < kRegs; ++i) {
      const Rule& u = row.r[i];
      switch (u.k) {
        case Kind::Unspec:
        case Kind::Same: break;
        case Kind::Undef: next[i].reset(); break;
        case Kind::Off: next[i] = read_stack(ctx, *cfa + static_cast<uint64_t>(u.v)); break;
        case Kind::ValOff: next[i] = *cfa + static_cast<uint64_t>(u.v); break;
        case Kind::Reg: next[i] = u.v >= 0 && u.v < kRegs ? regs[u.v] : std::nullopt; break;
        case Kind::Expr: {
          const auto a = eval(*e, u.e, u.elen, regs, ctx, *cfa);
          next[i] = a ? read_stack(ctx, *a) : std::nullopt;
          break;
        }
        case Kind::ValExpr: next[i] = eval(*e, u.e, u.elen, regs, ctx, *cfa); break;
      }
    }
    // The outermost frame marks its return address undefined.
    if (c.ra >= kRegs || row.r[c.ra].k == Kind::Undef || row.r[c.ra].k == Kind::Unspec) break;
    const std::optional<uint64_t> ra = next[c.ra];
    if (!ra || !*ra) break;
    next[kRip] = *ra;
    regs = next;
    exact = c.signal;  // a signal frame's return address is the interrupted instruction
    out.push_back(*ra);
  }
  return out;
}

}  // namespace montauk::unwind
