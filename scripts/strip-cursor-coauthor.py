"""Git msg-filter helper: remove Cursor Co-authored-by trailers."""
import sys

message = sys.stdin.read()
lines = [
    line
    for line in message.splitlines(keepends=True)
    if "Co-authored-by: Cursor" not in line
]
out = "".join(lines).rstrip() + "\n"
sys.stdout.write(out)
