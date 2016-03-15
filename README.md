An implementation of a mach-o parser using nom

This implementation essentially ignores the existance of 32bit mach objects.

As yet it's extremely incomplete, however if you're on OSX you can try:

    cargo run --example=reader `which cat`

To emit the data structure resulting from parsing your `cat` binary
