#pragma once

#include "ui/widget/LayoutRect.hpp"
#include <vector>

namespace montauk::ui::widget {

enum class FlexDirection {
    Row,     // Horizontal layout (left to right)
    Column,  // Vertical layout (top to bottom)
};

// One item participating in a flex layout. The component pointer is
// optional — flex layouts often arrange anonymous rects (panel slots
// inside a container) rather than literal Component instances. The
// solver only consults `constraints`.
struct FlexItem {
    LayoutConstraints constraints;
};

// Flexbox-inspired solver. Distributes a container's main-axis space
// across items per their flex_grow / flex_shrink, respects min/max,
// stretches the cross axis. Used everywhere montauk needs to lay out
// children — root left/right split, right-column panel stack, future
// nested layouts.
class FlexLayout {
public:
    FlexLayout() = default;

    void add_item(const LayoutConstraints& constraints);
    void set_direction(FlexDirection dir) { direction_ = dir; }
    void set_spacing(int spacing) { spacing_ = spacing; }
    void clear() { items_.clear(); }
    size_t item_count() const { return items_.size(); }

    // Compute layout for all items given available space.
    // Returns one LayoutRect per item, in the order they were added,
    // with x/y relative to the container's origin (0, 0).
    std::vector<LayoutRect> compute_layout(int available_width, int available_height);

private:
    std::vector<FlexItem> items_;
    FlexDirection direction_ = FlexDirection::Row;
    int spacing_ = 0;

    std::vector<int> compute_main_axis_sizes(int available_space);
    std::vector<int> compute_cross_axis_sizes(int available_space);

    int clamp_to_constraints(int size, const SizeConstraints& c, bool is_width) const;
    int get_min_size(const SizeConstraints& c, bool is_width) const;
    int get_max_size(const SizeConstraints& c, bool is_width) const;
};

} // namespace montauk::ui::widget
