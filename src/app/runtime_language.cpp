// SPDX-FileCopyrightText: The Open Annihilation Authors; see COPYRIGHT
// SPDX-License-Identifier: GPL-3.0-only

// The language the game shows its text in: chosen at start from 3.1c's
// command line, the player's setting and the operating system's preferred
// locales, and put in effect there and each time the setting changes. The
// game data's own texts follow it through 3.1c's keys (Translate.tdf, the
// units' <Language>Name and <Language>Description, the language folders);
// the engine's own words through the interface catalogue. Nothing here
// reaches the simulation, a saved game or what a shared game sends.

#include "language_state.hpp"
#include "oa/platform/system.hpp"
#include "oa/app/game_directory.hpp"
#include "oa/app/runtime.hpp"

#include "oa/app/asset_files.hpp"
#include "oa/data/defs/layout.hpp"
#include "oa/data/defs/locale.hpp"
#include "oa/data/languages/translation.hpp"
#include "oa/platform/locale.hpp"
#include "oa/ui/engine_settings.hpp"

#include <SDL3/SDL.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace oa::app {

namespace {

namespace languages = oa::data::languages;

/// The folder beside the game's other files that holds interface catalogue
/// files (oa/data/languages/interface_text.hpp), each a TDF file.
constexpr std::string_view kCatalogueFolder = "languages";

/// A catalogue file's extension, matched without regard to case.
constexpr std::string_view kCatalogueExtension = ".tdf";

/// Tells whether a file name ends in the catalogue's extension.
///
/// @param name the file name
/// @return true for a .tdf file, in any case
bool catalogue_file(std::string_view name) {
    if (name.size() <= kCatalogueExtension.size())
        return false;
    const auto tail = name.substr(name.size() - kCatalogueExtension.size());
    return std::equal(tail.begin(), tail.end(), kCatalogueExtension.begin(), [](char a, char b) {
        return (a >= 'A' && a <= 'Z' ? static_cast<char>(a - 'A' + 'a') : a) == b;
    });
}

} // namespace

void Runtime::destroy_language_state(LanguageState* state) noexcept {
    // The interface's lookups must not outlive the tables they read.
    if (state != nullptr) {
        languages::set_unit_texts(nullptr, {});
        languages::set_unit_text_sink(nullptr);
        languages::set_interface_language(nullptr, languages::english());
        languages::set_translation_hooks({});
    }
    delete state;
}

Runtime::LanguageState& Runtime::language_state() {
    if (!language_)
        language_.reset(new LanguageState{});
    return *language_;
}

void Runtime::start_language() {
    auto& state = language_state();
    state.system = &languages::preferred_language(oa::platform::locale::preferred_locales());
    // The loaders read every known language's unit texts, and the command
    // line's word when it names one no entry knows, as 3.1c reads it.
    state.sink_words.clear();
    for (const languages::Language& language : languages::known_languages())
        if (!language.game_name.empty())
            state.sink_words.emplace_back(language.game_name);
    const char* word = oa::app::command_line::launch_language(options_.launch);
    if (word != nullptr && languages::find_by_game_name(word) == nullptr)
        state.sink_words.emplace_back(word);
    state.sink_word_pointers.clear();
    for (const std::string& sink_word : state.sink_words)
        state.sink_word_pointers.push_back(sink_word.c_str());
    state.sink.context = &state;
    state.sink.languages = state.sink_word_pointers.data();
    state.sink.language_count = static_cast<uint32_t>(state.sink_word_pointers.size());
    state.sink.text = [](void* context,
                         const char* unit_name,
                         uint32_t language,
                         const char* name,
                         const char* description) {
        auto& owner = *static_cast<LanguageState*>(context);
        if (language < owner.sink_words.size())
            owner.unit_texts.add(unit_name, owner.sink_words[language], name, description);
    };
    languages::set_unit_text_sink(&state.sink);
    // Every screen and panel the game loads translates its texts, and looks
    // in its language's folders, through these.
    languages::set_translation_hooks(
        {this, translation_hook, [](void* runtime) {
             return static_cast<const Runtime*>(runtime)->game_language();
         }}
    );
    read_interface_catalogue();
    state.choice = oa::ui::engine_settings::stored_language(
        preference_values_, !options_.preferences_file.has_value()
    );
    apply_language();
}

void Runtime::read_interface_catalogue() {
    auto& state = language_state();
    const std::string base = oa::platform::program_directory();
    if (base.empty())
        return;
    const fs::path folder = path_from_utf8(base.c_str()) / path_from_utf8(kCatalogueFolder);
    std::error_code error;
    if (!fs::is_directory(folder, error))
        return;
    std::vector<fs::path> files;
    for (fs::directory_iterator entry(folder, error), end; !error && entry != end;
         entry.increment(error))
        if (entry->is_regular_file(error) && catalogue_file(path_to_utf8(entry->path().filename())))
            files.push_back(entry->path());
    // A later file's translation of a text replaces an earlier one's.
    std::sort(files.begin(), files.end());
    for (const fs::path& file : files) {
        std::ifstream input(file, std::ios::binary);
        std::string text;
        if (input)
            text.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
        std::string failure;
        if (!input || !state.catalogue.add(text, &failure))
            std::cerr << "open-annihilation: the interface catalogue " << path_to_utf8(file)
                      << " was not read" << (failure.empty() ? "" : ": ") << failure << '\n';
    }
}

void Runtime::set_language_choice(std::string_view choice) {
    auto& state = language_state();
    if (state.choice == choice)
        return;
    state.choice = std::string(choice);
    apply_language();
}

void Runtime::apply_language() {
    auto& state = language_state();
    const char* word = oa::app::command_line::launch_language(options_.launch);
    const languages::Language* named =
        word != nullptr ? languages::find_by_game_name(word) : nullptr;
    // The registry's words are string literals, so each word ends in a NUL.
    if (named != nullptr) {
        // 3.1c's command line names a known language: it decides the run's.
        state.shown = named;
        state.words = languages::data_words(*named, {});
    } else if (word != nullptr) {
        // A word no entry knows: the game data's texts in it, as 3.1c reads
        // them, and the engine's own words in English.
        state.shown = &languages::english();
        state.words = languages::data_words(languages::english(), word);
    } else {
        state.shown = &languages::chosen_language(state.choice, *state.system);
        state.words = languages::data_words(*state.shown, {});
    }
    state.data_word = data_word_for(state.choice);
    // The game data's translation table and fonts, loaded again only for a
    // new word.
    if (!state.loaded || state.loaded_word != state.data_word) {
        state.loaded = true;
        state.loaded_word = state.data_word;
        load_translations(game_language());
        load_common_fonts();
        // A language's fallbacks' tables, tried after its own.
        state.fallback_tables.clear();
        const auto files = asset_files(assets_);
        const auto path =
            std::string(oa::data::defs::directory_name(oa::data::defs::DataDirectory::gamedata)) +
            "\\translate.tdf";
        for (std::size_t index = 1; index < state.words.size(); ++index) {
            auto& table = state.fallback_tables.emplace_back(
                std::make_unique<LanguageState::FallbackTable>()
            );
            static_cast<void>(oa::data::defs::load_locale_table(
                &files, &table->table, path.c_str(), state.words[index].c_str()
            ));
        }
    }
    languages::set_unit_texts(&state.unit_texts, state.words);
    languages::set_interface_language(&state.catalogue, *state.shown);
}

const char* Runtime::game_translation(const char* text) const {
    if (text == nullptr)
        return nullptr;
    const char* translated = oa::data::defs::locale_translate(&translations_.table, text);
    if (translated != text)
        return translated;
    if (language_)
        for (const auto& table : language_->fallback_tables) {
            translated = oa::data::defs::locale_translate(&table->table, text);
            if (translated != text)
                return translated;
        }
    return nullptr;
}

const char* Runtime::translation_hook(void* runtime, const char* text) {
    return static_cast<const Runtime*>(runtime)->game_translation(text);
}

const char* Runtime::data_word_for(std::string_view choice) const {
    if (const char* word = oa::app::command_line::launch_language(options_.launch);
        word != nullptr) {
        const languages::Language* named = languages::find_by_game_name(word);
        return named != nullptr ? named->game_name.data() : word;
    }
    return languages::chosen_language(choice, system_language()).game_name.data();
}

const char* Runtime::game_language() const {
    if (!language_ || language_->data_word == nullptr || language_->data_word[0] == '\0')
        return nullptr;
    return language_->data_word;
}

const oa::data::languages::Language& Runtime::shown_language() const {
    return language_ ? *language_->shown : languages::english();
}

const oa::data::languages::Language& Runtime::system_language() const {
    return language_ ? *language_->system : languages::english();
}

const oa::data::defs::UnitTextSink* Runtime::unit_text_sink() {
    return &language_state().sink;
}

} // namespace oa::app
