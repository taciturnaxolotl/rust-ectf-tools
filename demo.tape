# VHS Demo — rust-ectf-tools
# Run: vhs demo.tape

Output demo.gif

Set Shell zsh
Set FontSize 15
Set Padding 20
Set Width 900
Set Height 520
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set CursorBlink false

# --- Build ---

Type "cargo build --release 2>&1 | tail -1"
Enter
Sleep 3s

# --- Alias for cleaner demo ---

Hide
Type "alias ectf-tools=./target/release/ectf-tools"
Enter
Sleep 500ms
Show

# --- Main help ---

Type "ectf-tools --help"
Enter
Sleep 3s

# --- HSM filesystem tools ---

Type "ectf-tools tools --help"
Enter
Sleep 3s

# --- Hardware bootloader tools ---

Type "ectf-tools hw --help"
Enter
Sleep 3s

# --- Create a test file ---

Type "echo 'hello from rust-ectf-tools!' > test.bin"
Enter
Sleep 500ms

# --- Write file to the HSM, pipe through less ---

Type "ectf-tools tools /dev/cu.usbmodemM43210021 write 1a2b3c 1 0x4321 test.bin -vv 2>&1 | less -R"
Enter
Sleep 3s
Down 3
Sleep 1s
Down 3
Sleep 1s
Down 3
Sleep 2s
Type "q"
Sleep 500ms

# --- List files on a connected HSM ---

Type "ectf-tools tools /dev/cu.usbmodemM43210021 list 1a2b3c"
Enter
Sleep 5s

Sleep 2s
