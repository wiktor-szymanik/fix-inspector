# Display and presentation

Open **Settings → Display** using the button at the right of primary navigation
or View → Settings. Changes are live and local to FIX Inspector;
they do not change Windows DPI, FIX bytes, parsing, serialization, forwarding,
session state, dictionaries, or the global Privacy masking policy.

## Controls

- Interface scale: **100%, 110%, 125%, 150%, 175%, 200%**.
- Message font size: **8–32 pt**.
- Table font size: **8–24 pt**.
- Enable presentation mode: temporary **150% / 18 pt / 15 pt** preset.

Font settings are base points at 100%. Interface zoom multiplies those sizes,
as well as ordinary control fonts and stylesheet spacing. For example, a 12 pt
message font at 150% renders at 18 pt. Display controls show the configured base
sizes. Rendering uses native Qt font metrics/widgets, not bitmap zoom.

Missing or invalid saved values fall back to **100% / 10 pt / 10 pt**, matching
the previous application's 10 pt typography. Message content uses Qt's system
fixed-width font. No font files are bundled or installed.

### Which widgets use each font?

**Message font:** raw FIX viewers, the shared structured/raw editors in Intercept,
Sender, Composer and Fuzzer, decoded History fields and groups, Decoder input/
raw/fields, Composer required/optional fields and repeating-group editors, and
plain-text diff/validation/dictionary-detail panes. History notes retain the
normal interface text size.

**Table font:** History, held-message queue, Sender timeline/related/connection
traffic, Fuzzer results and mutation list, message/template lists, dictionary
tables, and Proxy Behaviour tables. Decoded-field tables instead use Message font.

Table row heights grow with font metrics, including newly created tables. Column
widths and resize modes are retained, so existing user arrangements are not
reset. Very long cells may still require widening a column or horizontal
scrolling; display scaling does not discard fields or shorten their data.

### Presentation mode and persistence

Normal values are stored in the existing application INI under
`display/interface_scale`, `display/message_font_size`, and
`display/table_font_size`.

Presentation mode keeps the normal values separately. Edits/shortcuts used while
it is enabled are temporary. Disabling it restores the normal configuration;
restarting also uses the normal values, even if the application was closed while
presentation mode was enabled. No project-format migration is needed.

## Shortcuts

| Action | Shortcut |
|---|---|
| Next/previous interface scale | Ctrl+Plus / Ctrl+Minus |
| Alternative zoom-in key | Ctrl+= |
| Reset interface scale only | Ctrl+0 |
| Change message font over a message pane/field viewer | Ctrl+mouse wheel |
| Change interface scale elsewhere in the window | Ctrl+mouse wheel |

Keyboard Plus/Minus always adjust interface scale, including when an editor has
focus. Existing Copy, editing and application shortcuts are retained. A wheel
gesture is consumed as a display action and does not change a focused field or
spinbox value.

## Layout and limitations

Workspace/settings pages scroll when their contents exceed the viewport; tab
bars retain navigation arrows. The status labels also share a horizontally
scrollable row, so large text cannot force the main window wider than the screen.
Native Qt dialogs and dynamically created message editors inherit the scale.

Operating-system-native file pickers are controlled by Windows and may not
honor the application scale. This feature deliberately does not replace them
or alter OS settings. No native-widget recreation or restart is required.

## Verification / Windows checklist

Automated display regressions cover fonts without payload changes, table geometry,
temporary presentation settings, persistence, shortcuts, masking and editor state.
Offscreen tests may register existing Windows fonts in the test process; no font files
are distributed. Interactive projector and native file-dialog behavior still requires
manual review.

For interactive verification:

1. Open an existing History message and a Sender draft; change Message font
   from 12 to 20. Confirm text grows while values and masking remain unchanged.
2. Change Table font from 11 to 16. Confirm row height, selection and History
   entries remain intact; resize a column normally.
3. Set normal values to 110% / 13 / 11. Toggle presentation mode on/off and
   confirm restoration. Close while presentation mode is on and reopen.
4. Try Ctrl+Plus, Ctrl+Minus, Ctrl+0, Ctrl+wheel and Ctrl+C in a raw editor.
5. At 150% and 200%, visit Settings, Proxy → History, Sender and Composer; use
   scrollbars and tab arrows to reach content outside the viewport.

