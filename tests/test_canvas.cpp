#include "minitest.hpp"
#include "ui/widget/Canvas.hpp"
#include "ui/widget/Component.hpp"
#include "ui/widget/LayoutRect.hpp"
#include "model/Snapshot.hpp"

using namespace montauk::ui::widget;

// Bounds & clipping: writes past rect are silent no-ops; reads return a dummy.
TEST(canvas_bounds_clipping_silent) {
  Canvas c(10, 5);
  c.put(15, 10, "X", {});         // way out of bounds
  c.put(-1, 0, "Y", {});          // negative
  c.put(0, -1, "Z", {});          // negative
  // In-bounds cells unchanged
  ASSERT_EQ(c.at(0, 0).content, std::string(" "));
  ASSERT_EQ(c.at(9, 4).content, std::string(" "));
  // Out-of-bounds read returns the static dummy, doesn't crash
  const Cell& dummy = c.at(15, 10);
  ASSERT_EQ(dummy.content, std::string(" "));
}

// put/at round-trip preserves content and style.
TEST(canvas_put_at_roundtrip) {
  Canvas c(10, 5);
  Style s{Color::Red, Color::Default, Attribute::Bold};
  c.put(3, 2, "A", s);
  ASSERT_EQ(c.at(3, 2).content, std::string("A"));
  ASSERT_TRUE(c.at(3, 2).style.fg == Color::Red);
  ASSERT_TRUE(has_attribute(c.at(3, 2).style.attr, Attribute::Bold));
  // Neighboring cells untouched
  ASSERT_EQ(c.at(2, 2).content, std::string(" "));
  ASSERT_EQ(c.at(4, 2).content, std::string(" "));
}

// draw_text returns x after the last char; clips at right edge.
TEST(canvas_draw_text_return_and_clipping) {
  Canvas c(10, 3);
  int end = c.draw_text(0, 0, "hello", {});
  ASSERT_EQ(end, 5);
  ASSERT_EQ(c.at(0, 0).content, std::string("h"));
  ASSERT_EQ(c.at(4, 0).content, std::string("o"));
  ASSERT_EQ(c.at(5, 0).content, std::string(" "));

  // Long text clips at canvas width — first 10 cells filled, no crash
  Canvas c2(10, 1);
  c2.draw_text(0, 0, "abcdefghijklmnop", {});
  ASSERT_EQ(c2.at(0, 0).content, std::string("a"));
  ASSERT_EQ(c2.at(9, 0).content, std::string("j"));

  // Draw at negative y is a no-op (returns x)
  Canvas c3(10, 3);
  int r = c3.draw_text(2, -1, "oops", {});
  ASSERT_EQ(r, 2);
  ASSERT_EQ(c3.at(2, 0).content, std::string(" "));
}

// draw_text parses embedded ANSI SGR codes into per-cell styles.
TEST(canvas_draw_text_sgr_parsing) {
  Canvas c(20, 1);
  // "\x1b[31m" sets red fg, "\x1b[0m" resets.
  c.draw_text(0, 0, "\x1b[31mred\x1b[0m X", {});
  // "red" cells should be fg=Red
  ASSERT_TRUE(c.at(0, 0).style.fg == Color::Red);
  ASSERT_TRUE(c.at(1, 0).style.fg == Color::Red);
  ASSERT_TRUE(c.at(2, 0).style.fg == Color::Red);
  // After reset, space + X default
  ASSERT_TRUE(c.at(3, 0).style.fg == Color::Default);
  ASSERT_EQ(c.at(4, 0).content, std::string("X"));
  ASSERT_TRUE(c.at(4, 0).style.fg == Color::Default);

  // Truecolor SGR: "\x1b[38;2;10;20;30m"
  Canvas c2(10, 1);
  c2.draw_text(0, 0, "\x1b[38;2;10;20;30mQ", {});
  ASSERT_TRUE(is_truecolor(c2.at(0, 0).style.fg));
  ASSERT_EQ(static_cast<int>(color_r(c2.at(0, 0).style.fg)), 10);
  ASSERT_EQ(static_cast<int>(color_g(c2.at(0, 0).style.fg)), 20);
  ASSERT_EQ(static_cast<int>(color_b(c2.at(0, 0).style.fg)), 30);
}

// draw_rect draws a 4-corner + 4-edge Unicode border, interior untouched.
TEST(canvas_draw_rect_border) {
  Canvas c(5, 4);
  c.draw_rect(0, 0, 5, 4, {});
  // Corners
  ASSERT_EQ(c.at(0, 0).content, std::string("┌"));
  ASSERT_EQ(c.at(4, 0).content, std::string("┐"));
  ASSERT_EQ(c.at(0, 3).content, std::string("└"));
  ASSERT_EQ(c.at(4, 3).content, std::string("┘"));
  // Horizontal edges
  ASSERT_EQ(c.at(1, 0).content, std::string("─"));
  ASSERT_EQ(c.at(3, 3).content, std::string("─"));
  // Vertical edges
  ASSERT_EQ(c.at(0, 1).content, std::string("│"));
  ASSERT_EQ(c.at(4, 2).content, std::string("│"));
  // Interior untouched
  ASSERT_EQ(c.at(2, 2).content, std::string(" "));
}

// fill_rect fills w*h cells and clips at canvas bounds.
TEST(canvas_fill_rect_clipping) {
  Canvas c(10, 5);
  Cell fill{"#", Style{Color::Green}};
  c.fill_rect(2, 1, 4, 2, fill);
  // Filled region
  ASSERT_EQ(c.at(2, 1).content, std::string("#"));
  ASSERT_EQ(c.at(5, 2).content, std::string("#"));
  // Just outside
  ASSERT_EQ(c.at(1, 1).content, std::string(" "));
  ASSERT_EQ(c.at(6, 1).content, std::string(" "));
  // Off-canvas: must not crash
  c.fill_rect(8, 3, 100, 100, fill);
  ASSERT_EQ(c.at(8, 3).content, std::string("#"));
  ASSERT_EQ(c.at(9, 4).content, std::string("#"));
}

// blit copies cells; respects source and dest bounds on both sides.
TEST(canvas_blit_clipping) {
  Canvas src(4, 2);
  src.put(0, 0, "A", {});
  src.put(1, 0, "B", {});
  src.put(2, 0, "C", {});
  src.put(3, 0, "D", {});

  Canvas dst(10, 5);
  dst.blit(src, 5, 1);
  ASSERT_EQ(dst.at(5, 1).content, std::string("A"));
  ASSERT_EQ(dst.at(8, 1).content, std::string("D"));

  // Blit near the right edge — D goes out of bounds, A/B/C survive
  Canvas dst2(7, 5);
  dst2.blit(src, 5, 2);  // would write at x=5,6,7,8 — 7 and 8 out of bounds
  ASSERT_EQ(dst2.at(5, 2).content, std::string("A"));
  ASSERT_EQ(dst2.at(6, 2).content, std::string("B"));
  // Past the edge: no crash, nothing written
}

// TestWidget proves Component virtual dispatch compiles and works end-to-end.
namespace {
class TestWidget : public Component {
public:
  void render(
      Canvas& canvas,
      const LayoutRect& rect,
      const montauk::model::Snapshot& /*snap*/) override {
    canvas.draw_text(rect.x, rect.y, "hello", {Color::Cyan});
  }
};
}  // namespace

TEST(component_virtual_dispatch) {
  Canvas c(20, 3);
  montauk::model::Snapshot snap;
  LayoutRect rect{2, 1, 18, 2};

  TestWidget w;
  Component* ptr = &w;
  ptr->render(c, rect, snap);

  ASSERT_EQ(c.at(2, 1).content, std::string("h"));
  ASSERT_EQ(c.at(6, 1).content, std::string("o"));
  ASSERT_TRUE(c.at(2, 1).style.fg == Color::Cyan);
  // Outside rect.y: untouched
  ASSERT_EQ(c.at(2, 0).content, std::string(" "));
}
