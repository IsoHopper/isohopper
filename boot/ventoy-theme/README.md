# IsoHopper USB menu theme

Windows preparation installs this fixed theme on the first, exFAT partition:

- `ventoy.json` becomes `/ventoy/ventoy.json`.
- `theme.txt` and the PNG files become `/ventoy/isohopper/`.

The helper embeds these files, reserves their destination paths, checks their
allocated size, and verifies their bytes before sealing the prepared image.
They do not count as user images. The pinned Ventoy boot binaries are unchanged.

This is a [Ventoy GRUB theme](https://www.ventoy.net/en/plugin_theme.html), separate
from the experimental Rust UEFI launcher and Studio's visual preview. Entries
and tool shortcuts come from Ventoy. An empty drive keeps Ventoy's empty-library
message; copying supported images onto the drive populates its menu.

The initial layout uses 1024×768, the engine's existing font, a charcoal background
and a rounded blue selection outline with a wider left marker. `logo.png` is the
existing 32-pixel application icon, unchanged. `background.png` supplies the
rounded menu and keyboard panels. The nine `select_*.png` files form the selected
row's GRUB frame. Keep `@VTOY_HOTKEY_TIP@` in one location so the
engine's shortcuts appear once. F7 switches to Ventoy's text fallback.

When changing these assets, run the helper's `windows_stage` tests, the Windows
disposable-VHD staging test, and inspect the actual Ventoy menu in a virtual
machine. Studio screenshots alone do not validate the boot menu.
