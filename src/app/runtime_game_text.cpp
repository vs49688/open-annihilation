// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

// Game text in the modern fonts: the bundled fonts, opened once and shared,
// the lines they draw at the text size, kept for the frames that draw them
// again, the game-text hooks the text loops reach them and the player's
// settings through, how large the match's text is painted where it lies,
// and lines painted on the match's RGB layer, reduced to the palette, their
// shadow over the Full tier's overlay canvas left to the card.

#include "oa/app/runtime.hpp"
#include "oa/app/view_rules.hpp"

#include "oa/platform/text_font.hpp"
#include "oa/base/threads.hpp"
#include "oa/present/game_text.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace oa::app {

namespace {

namespace text_font = oa::platform::text_font;

/// The most drawn lines kept before the store starts again.
constexpr std::size_t kept_lines = 512;

/// The pixel size and weight of each face at a scale of 1 and the game
/// fonts' size: DejaVu Sans Bold 14 px stands as tall as hattfont12, Bold
/// 11 px as hattfont11, and DejaVu Sans 11 px matches CONSOLE.FNT's
/// x-height.
struct FaceSize {
    int32_t pixel_size{};
    text_font::Weight weight{};
};

constexpr FaceSize message_face{14, text_font::Weight::bold};
constexpr FaceSize status_face{11, text_font::Weight::bold};
constexpr FaceSize label_face{11, text_font::Weight::regular};

/// The bundled fonts, opened on first use, and the lines they drew, by
/// face, scale and text; a null line is one they could not draw.
struct ModernFonts {
    base::threads::Mutex mutex{};
    bool opened{};
    std::unique_ptr<text_font::FontStack> stack{};
    std::unordered_map<std::string, std::shared_ptr<const oa::present::TextMask>> lines{};
};

ModernFonts& modern_fonts() {
    static ModernFonts fonts;
    return fonts;
}

/// Opens the fonts the first time they are asked for; null when they cannot be.
text_font::FontStack* opened_stack(ModernFonts& fonts) {
    if (!fonts.opened) {
        fonts.opened = true;
        try {
            fonts.stack = text_font::FontStack::open(text_font::bundled_font_directory());
        } catch (const std::exception&) {
            fonts.stack.reset();
        }
    }
    return fonts.stack.get();
}

/// The style a face is drawn in at a scale and text size: hinted to whole
/// pixels, one bit a pixel, as crisp as the game's own fonts at every size.
text_font::Style face_style(oa::present::TextFace face, int32_t scale, int32_t text_size) {
    const FaceSize size = face == oa::present::TextFace::message  ? message_face
                          : face == oa::present::TextFace::status ? status_face
                                                                  : label_face;
    text_font::Style style;
    style.pixel_size = std::clamp(
        oa::present::face_pixel_size(size.pixel_size, scale, text_size),
        1,
        text_font::max_pixel_size
    );
    style.weight = size.weight;
    style.rendering = text_font::Rendering::mono;
    return style;
}

/// Draws a line in the stack; null when it cannot.
std::shared_ptr<const oa::present::TextMask>
draw_mask(text_font::FontStack& stack, std::string_view text, const text_font::Style& style) {
    const auto drawn = stack.draw(text, style);
    const auto placements = stack.layout(text, style);
    const auto characters = text_font::decode_utf8(text);
    if (!drawn || !placements || !characters)
        return nullptr;
    auto mask = std::make_shared<oa::present::TextMask>();
    mask->width = drawn->width;
    mask->height = drawn->height;
    mask->baseline = drawn->baseline;
    mask->origin = drawn->origin;
    mask->advance = drawn->advance;
    mask->alpha = drawn->alpha;
    // The placements are the visible characters'; the others leave the pen.
    std::size_t placed = 0;
    int32_t pen = 0;
    for (const char32_t character : *characters) {
        if (!text_font::is_invisible(character) && placed < placements->size()) {
            const auto& placement = (*placements)[placed++];
            pen = placement.pen + placement.advance;
        }
        mask->character_ends.push_back(pen);
    }
    return mask;
}

} // namespace

GameTextHooksInstall::~GameTextHooksInstall() {
    if (runtime != nullptr && oa::present::game_text_hooks().context == runtime)
        oa::present::set_game_text_hooks({});
}

bool Runtime::modern_fonts_open() {
    auto& fonts = modern_fonts();
    const base::threads::LockGuard lock(fonts.mutex);
    return opened_stack(fonts) != nullptr;
}

bool Runtime::game_text_utf8() const {
    const auto& text = ui_rules().text_rendering;
    return text.enabled && text.unicode;
}

oa::present::TextSettings Runtime::game_text_settings() const {
    oa::present::TextSettings settings;
    settings.style = text_style();
    settings.style.modern_fonts = settings.style.modern_fonts && modern_fonts_open();
    settings.utf8 = game_text_utf8();
    return settings;
}

std::string Runtime::typed_game_text(std::string_view typed) const {
    return oa::present::encode_game_text(typed, game_text_utf8());
}

Runtime::PanelText::PanelText(Runtime& owner) noexcept : runtime(&owner), kept(owner.text_place_) {
    owner.text_place_ = TextPlace::panel;
}

Runtime::PanelText::~PanelText() {
    runtime->text_place_ = kept;
}

int32_t Runtime::painted_text_size(const oa::present::TextRun& run) const noexcept {
    // A panel is laid out for the game's fonts: its text never grows past
    // them.
    if (text_place_ == TextPlace::panel)
        return std::min(run.size, oa::present::game_font_text_size);
    return run.size;
}

int32_t Runtime::painted_baseline(int32_t font_baseline, int32_t size) const noexcept {
    // Over the battlefield a line's top stays at the pen and its baseline
    // moves with the size; in a panel the text keeps the font's baseline.
    if (text_place_ == TextPlace::panel)
        return font_baseline;
    return oa::present::sized_length(font_baseline, size);
}

int Runtime::paint_modern_text(
    const oa::present::TextLayers& layers, int x, int baseline_y, std::array<uint8_t, 3> color
) {
    auto& dest = paint_target();
    const bool has_palette = match_palette_ != oa::PaletteBytes{};
    auto canvas = oa::present::rgb_canvas(
        dest.rgb,
        static_cast<int32_t>(dest.width),
        static_cast<int32_t>(dest.height),
        has_palette ? std::span<const uint8_t>(match_palette_) : std::span<const uint8_t>{}
    );
    // The Full tier's overlay canvas holds no world: over it the card
    // darkens the world under the shadow at the shadow's alpha, holds it to
    // the outline grey at the most under the outline, which is black over
    // black ground and the grey over ground lighter than it, and blends
    // the letters' colour over it where they cover a pixel in part, each
    // at its share in 256ths.
    if (paints_full_canvas()) {
        canvas.see_through = full_overlay_key();
        canvas.world_user = this;
        canvas.world_run = [](void* user, const oa::present::TextWorldRun& run) {
            auto& runtime = *static_cast<Runtime*>(user);
            switch (run.layer) {
            case oa::present::TextWorldLayer::shadow: {
                constexpr uint32_t shadow_opacity =
                    (uint32_t{oa::present::text_shadow_alpha} * 256U + 127U) / 255U;
                std::ignore = runtime.paint_world_blend(
                    run.x, run.y, run.width, 1, oa::present::text_shade_color, shadow_opacity
                );
                break;
            }
            case oa::present::TextWorldLayer::outline:
                std::ignore = runtime.paint_world_minimum(
                    run.x, run.y, run.width, 1, oa::present::text_outline_color
                );
                break;
            case oa::present::TextWorldLayer::letter:
                std::ignore = runtime.paint_world_blend(
                    run.x,
                    run.y,
                    run.width,
                    1,
                    run.color,
                    (uint32_t{run.coverage} * 256U + 127U) / 255U
                );
                break;
            }
        };
    }
    oa::present::lay_text(canvas, layers, x, baseline_y, color);
    return layers.advance;
}

void Runtime::install_game_text_hooks() {
    oa::present::GameTextHooks hooks{};
    hooks.context = this;
    hooks.settings = [](void* context) {
        return static_cast<const Runtime*>(context)->game_text_settings();
    };
    hooks.draw = [](void*,
                    std::string_view text,
                    oa::present::TextFace face,
                    int32_t scale,
                    int32_t size) -> std::shared_ptr<const oa::present::TextMask> {
        if (text.empty() || text.size() > text_font::max_text_bytes)
            return nullptr;
        const auto style = face_style(face, scale, size);
        std::string key;
        key.push_back(static_cast<char>(face));
        key += std::to_string(style.pixel_size);
        key.push_back('\0');
        key.append(text);
        auto& fonts = modern_fonts();
        const base::threads::LockGuard lock(fonts.mutex);
        if (const auto found = fonts.lines.find(key); found != fonts.lines.end())
            return found->second;
        auto* stack = opened_stack(fonts);
        if (stack == nullptr)
            return nullptr;
        auto mask = draw_mask(*stack, text, style);
        if (fonts.lines.size() >= kept_lines)
            fonts.lines.clear();
        fonts.lines.emplace(std::move(key), mask);
        return mask;
    };
    // A match draws in its palette, the frontend in its screen's.
    hooks.palette = [](void* context) -> std::span<const uint8_t> {
        const auto& runtime = *static_cast<const Runtime*>(context);
        const oa::PaletteBytes& palette =
            runtime.screen_ == Screen::match ? runtime.match_palette_ : runtime.screen_palette();
        return palette;
    };
    oa::present::set_game_text_hooks(hooks);
    game_text_hooks_.runtime = this;
}

} // namespace oa::app
