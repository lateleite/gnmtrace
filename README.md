# gnmtrace

gnmtrace is an ***in development*** PlayStation 4 frame tracer/dumper available as a MiraHEN plugin.

Its current purpose is supporting emulator development.

Note that this tool is a work in progress and will likely break with most games/applications.

**WARNING**: Debug builds are currently unreliable and will likely cause an out-of-error memory in your system.

## Usage

To use gnmtrace, load MiraHEN and then:

- Copy `gnmtrace.prx` to a Substitute directory, such as `/data/mira/substitute/CUSA00000/gnmtrace.prx` (where CUSA00000 is your target application's title ID)
- Launch the application
- Press the L1+X combo to begin a frame trace
- Retrieve the trace data from `/data/gnmtrace/`

## Building

You need the following tools to build the projects:

- [Zig 0.17.0](https://ziglang.org/download)
- [OpenOrbis Toolchain](https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain)

Then go this project's root directory and run

```bash
export OO_PS4_TOOLCHAIN=/path/to/OpenOrbis-PS4-Toolchain
zig build --release=fast
```

If successful, you should find your `gnmtrace.prx` plugin file inside the `zig-out` directory.

## License

This project is licensed under the MIT license, see [LICENSE](LICENSE) for more information.
