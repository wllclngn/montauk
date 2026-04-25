#pragma once

#include "model/Snapshot.hpp"
#include "ui/widget/InputEvent.hpp"
#include <memory>

namespace montauk::ui {

// Owns the entire TUI: process table, help overlay, right-column toggles,
// the layout solver. main.cpp creates one Renderer, drives input through
// handle_input, and calls render() each frame.
class Renderer {
 public:
  Renderer();
  ~Renderer();

  // Composes one frame and writes it to stdout in a single atomic write.
  void render(const montauk::model::Snapshot& s);

  // Dispatches an input event. Routing rules:
  //   - Help overlay visible:        all events go to the overlay.
  //   - ProcessTable in search mode: all events go to the table.
  //   - Otherwise:                   global keys handled here, others
  //                                  forwarded to the focused widget.
  void handle_input(const widget::InputEvent& event);

  [[nodiscard]] bool should_quit() const;
  [[nodiscard]] int  sleep_ms() const;

  // Seed the render state from config at startup. Idempotent — call once.
  void seed_from_config();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace montauk::ui
