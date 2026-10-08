const std = @import("std");
const orbis = @import("open_orbis_zig");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .ps4,
        },
    });
    const optimize = b.standardOptimizeOption(.{});

    if (target.result.os.tag != .ps4) {
        @panic(
            \\PS4 is the only supported target, please set it as your build target.
            \\For example: zig build -Dtarget=x86_64-ps4
            \\
        );
    }

    //
    // dependencies
    //
    const dep_gnm = b.dependency("freegnm", .{
        .target = target,
        .optimize = optimize,
    });
    const mod_gnm = dep_gnm.module("gnm");

    const dep_orbis = b.dependency("open_orbis_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const mod_orbis = dep_orbis.module("orbis");
    const lib_musl = dep_orbis.artifact("musl");
    const wf_syslibs = dep_orbis.namedWriteFiles("sys_libs");

    const dep_lz4u = b.dependency("lz4u", .{});
    const mod_lz4u = dep_lz4u.module("lz4u");

    // OpenOrbis/musl needs libkernel
    lib_musl.root_module.addLibraryPath(wf_syslibs.getDirectory());
    lib_musl.root_module.linkSystemLibrary("kernel", .{});
    // freegnm needs libc (for now), so link OpenOrbis-musl to it
    mod_gnm.addLibraryPath(wf_syslibs.getDirectory());
    mod_gnm.linkLibrary(lib_musl);

    // libc CRT for non-PIE executables
    // const obj_crt_lib = dep_orbis.artifact("crt_lib");
    // setup ModuleParam section
    const obj_moduleparam = orbis.buildModuleParam(b, dep_orbis, target, .{});

    //
    // library
    //
    const lib_trace = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "gnmtrace",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .imports = &.{
                .{ .name = "gnm", .module = mod_gnm },
                .{ .name = "orbis", .module = mod_orbis },
                .{ .name = "lz4u", .module = mod_lz4u },
            },
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
        .use_lld = true,
    });

    // add OpenOrbis include and library paths
    lib_trace.link_eh_frame_hdr = true;
    lib_trace.link_gc_sections = false;
    // lib_trace.root_module.addObject(obj_crt_lib);
    lib_trace.root_module.addObject(obj_moduleparam);
    lib_trace.setLinkerScript(dep_orbis.path("link.x"));

    // system libraries
    lib_trace.root_module.addLibraryPath(wf_syslibs.getDirectory());
    lib_trace.root_module.linkSystemLibrary("kernel", .{});
    lib_trace.root_module.linkSystemLibrary("ScePad", .{});
    lib_trace.root_module.linkSystemLibrary("SceGnmDriver", .{});
    lib_trace.root_module.linkSystemLibrary("SceUserService", .{});
    lib_trace.root_module.linkSystemLibrary("SceVideoOut", .{});

    //
    // create fakeself PRX out of new shared library
    //
    const prx_file = orbis.createPrx(b, lib_trace, "gnmtrace.prx", .{});

    //
    // install PRX
    //
    b.installArtifact(lib_trace);
    b.getInstallStep().dependOn(&b.addInstallFile(prx_file, "gnmtrace.prx").step);

    //
    // check stage for ZLS
    //
    const step_check = b.step("check", "Check if the project compiles");

    const check_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "check-gnmtrace",
        .root_module = lib_trace.root_module,
    });
    step_check.dependOn(&check_lib.step);
}
