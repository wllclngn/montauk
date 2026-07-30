// The Sixel encoder, which had no coverage at all before this file.
//
// It was rewritten from a 216-pass loop nest (ask "which pixels are color p"
// for each of the 216 color-cube entries, requantizing every pixel each time)
// into a single pass that quantizes each pixel once and deposits its bit into
// its own color's row. That is an O(216 * w * h) -> O(w * h) change on the
// render path of every Sixel terminal, and the ONLY thing that makes it safe is
// that the output is byte-identical.
//
// So this file carries the 216-pass version as a reference implementation and
// asserts the two agree, rather than freezing a golden string: a golden would
// prove the output stopped changing, while this proves it still equals the
// algorithm it replaced.

#include "minitest.hpp"
#include "ui/widget/GraphicsProtocol.hpp"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

using montauk::ui::widget::GraphicsEmitter;

// The original loop nest, verbatim in structure, as the oracle.
static std::string reference_bands(const uint8_t* rgba, int w_px, int h_px) {
  std::ostringstream oss;
  for (int band_y = 0; band_y < h_px; band_y += 6) {
    int band_h = std::min(6, h_px - band_y);
    for (int p = 0; p < 216; ++p) {
      bool any = false;
      std::string row;
      row.reserve(static_cast<size_t>(w_px));
      for (int x = 0; x < w_px; ++x) {
        uint8_t sixel_bits = 0;
        for (int dy = 0; dy < band_h; ++dy) {
          const uint8_t* px = rgba + ((band_y + dy) * w_px + x) * 4;
          int pr = (px[0] + 25) / 51;
          int pg = (px[1] + 25) / 51;
          int pb = (px[2] + 25) / 51;
          int qidx = pr * 36 + pg * 6 + pb;
          if (qidx == p) sixel_bits |= (1u << dy);
        }
        if (sixel_bits) any = true;
        row += static_cast<char>('?' + sixel_bits);
      }
      if (any) oss << '#' << p << row << '$';
    }
    oss << '-';
  }
  return oss.str();
}

// The real encoder, called DIRECTLY. Going through emit_full was the first
// attempt and it proved nothing: emit_full returns an empty string unless a
// Sixel terminal was detected, and a headless test run detects Protocol::None,
// so both assertions passed through a fallback branch without ever executing
// the code under test. That is the same "gate passes while proving nothing"
// failure this release found three times elsewhere, so the encoder was hoisted
// out of emit_full to be reachable.
static std::string emitted_bands(const uint8_t* rgba, int w_px, int h_px) {
  return montauk::ui::widget::sixel_bands(rgba, w_px, h_px);
}

static std::vector<uint8_t> make_image(int w, int h, int seed) {
  std::vector<uint8_t> px(static_cast<size_t>(w) * h * 4);
  uint32_t st = static_cast<uint32_t>(seed) | 1u;
  for (size_t i = 0; i < px.size(); i += 4) {
    st ^= st << 13; st ^= st >> 17; st ^= st << 5;
    px[i + 0] = static_cast<uint8_t>(st & 0xFF);
    px[i + 1] = static_cast<uint8_t>((st >> 8) & 0xFF);
    px[i + 2] = static_cast<uint8_t>((st >> 16) & 0xFF);
    px[i + 3] = 255;
  }
  return px;
}

TEST(sixel_single_pass_matches_the_216_pass_reference) {
  // Sizes chosen for the band arithmetic: an exact multiple of 6, one short,
  // one over, and a single row -- the partial-band path is where an inverted
  // loop nest is most likely to differ.
  for (auto [w, h] : {std::pair{7, 12}, std::pair{7, 11}, std::pair{7, 13},
                      std::pair{1, 1}, std::pair{16, 6}, std::pair{3, 18}}) {
    auto px = make_image(w, h, w * 31 + h);
    std::string got = emitted_bands(px.data(), w, h);
    ASSERT_TRUE(!got.empty());
    ASSERT_EQ(got, reference_bands(px.data(), w, h));
  }
}

TEST(sixel_reference_is_stable_for_flat_and_banded_input) {
  // A flat image exercises the "one color touched per band" path the single
  // pass optimizes hardest; a two-tone image exercises row clearing between
  // bands, which is where a missed reset would leak bits from the band above.
  const int w = 12, h = 18;
  std::vector<uint8_t> flat(static_cast<size_t>(w) * h * 4, 0);
  for (size_t i = 3; i < flat.size(); i += 4) flat[i] = 255;
  std::string ref_flat = reference_bands(flat.data(), w, h);
  ASSERT_EQ(emitted_bands(flat.data(), w, h), ref_flat);

  std::vector<uint8_t> banded(static_cast<size_t>(w) * h * 4, 0);
  for (int y = 0; y < h; ++y)
    for (int x = 0; x < w; ++x) {
      uint8_t* p = banded.data() + (static_cast<size_t>(y) * w + x) * 4;
      p[0] = (y < h / 2) ? 255 : 0;
      p[1] = 0;
      p[2] = (y < h / 2) ? 0 : 255;
      p[3] = 255;
    }
  std::string ref_band = reference_bands(banded.data(), w, h);
  ASSERT_EQ(emitted_bands(banded.data(), w, h), ref_band);
  // Independent of the emitter: the two images must not encode alike, or the
  // reference itself is degenerate and the comparison above proves nothing.
  ASSERT_NE(ref_flat, ref_band);
}
