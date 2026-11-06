# Recorded with vhs 0.12.1: `vhs assets/demo.tape` from the repository root,
# with `pocgate` on PATH (go build -o pocgate ./cmd/pocgate).
#
# The sleeps cover the measured runtime of each command on the recording
# machine (demo ~9 s, attest verify well under 1 s) plus a margin, so the GIF
# shows the run rather than an empty prompt. `pocgate demo` prints its own
# elapsed time, so the recording cannot overstate the speed.
Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 640

Type "pocgate demo" Enter
Sleep 14s
Type "pocgate attest verify --pubkey .pocgate/evidence/latest.json.pub .pocgate/evidence/latest.json" Enter
Sleep 4s
