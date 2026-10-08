const std = @import("std");
const fs = std.fs;
const Io = std.Io;
const log = std.log.scoped(.gnmtrace);
const mem = std.mem;

const orbis = @import("orbis");
const vo = orbis.VideoOut;
const us = orbis.UserService;
const Pad = orbis.Pad;

const Frametracer = @import("frametracer.zig");
const mira = @import("mira.zig");

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
const allocator = debug_allocator.allocator();
var threaded: Io.Threaded = undefined;

var my_pad: ?MyPad = null;
var tracer: ?Frametracer = null;
var proc_info: ?mira.ProcessInfo = null;

const MyPad = struct {
    controller: Pad.Controller,
    owner_id: us.UserId,
    kind: Pad.Controller.PortType,
    index: i32,
};

extern "kernel" fn sceKernelWrite(fd: std.os.ps4.fd_t, buf: [*]const u8, nbyte: usize) i32;

export fn _init(args: usize, argp: *const anyopaque) callconv(.c) c_int {
    _ = args;
    _ = argp;

    const my_string = "!!! module_start here !!!!\n";
    _ = sceKernelWrite(1, my_string.ptr, my_string.len);

    moduleStart() catch |err| {
        log.err("moduleStart exited with error {t}\n", .{err});
        return 1;
    };
    return 0;
}

export fn _fini(args: usize, argp: *const anyopaque) callconv(.c) c_int {
    _ = args;
    _ = argp;
    const my_string = "!!! module_stop here !!!!\n";
    _ = sceKernelWrite(1, my_string.ptr, my_string.len);

    moduleStop() catch |err| {
        log.err("moduleStop exited with error {t}\n", .{err});
        return 1;
    };
    return 0;
}

fn moduleStart() !void {
    log.info("gnmtrace: Setting up... ", .{});

    proc_info = mira.ownProcessInfo() catch |err| {
        log.err("Failed to get own process info with {t}. Is Mira loaded?", .{err});
        return err;
    };

    const title_id = mem.sliceTo(&proc_info.?.title_id, 0);
    const process_name = mem.sliceTo(&proc_info.?.process_name, 0);
    const eboot_base_address = proc_info.?.process_base_address orelse {
        log.err("Process' base address is null! Is this a Mira bug?", .{});
        return error.NullBaseAddress;
    };

    log.info("Title ID: {s} Process name: {s} Process base: {any}", .{
        title_id,
        process_name,
        eboot_base_address,
    });

    //
    // VideoOut hooks
    //
    // TODO: unhook on error
    originalFuncs.videoOutOpen = @ptrCast(try hookImport("sceVideoOutOpen", &hkSceVideoOutOpen));
    originalFuncs.videoOutRegisterBuffers = @ptrCast(try hookImport("sceVideoOutRegisterBuffers", &hkSceVideoOutRegisterBuffers));
    originalFuncs.videoOutSubmitFlip = @ptrCast(try hookImport("sceVideoOutSubmitFlip", &hkSceVideoOutSubmitFlip));

    //
    // Pad hooks
    // (optional)
    //
    if (hookImport("scePadOpen", &hkScePadOpen)) |orig_fn|
        originalFuncs.padOpen = @ptrCast(orig_fn)
    else |_| {}

    //
    // GnmDriver hooks
    // they're all optional
    //
    if (hookImport("sceGnmSubmitDone", &hkSceGnmSubmitDone)) |orig_fn|
        originalFuncs.gnmSubmitDone = @ptrCast(orig_fn)
    else |_| {}
    if (hookImport("sceGnmSubmitCommandBuffers", &hkSceGnmSubmitCommandBuffers)) |orig_fn|
        originalFuncs.gnmSubmitCommandBuffers = @ptrCast(orig_fn)
    else |_| {}
    if (hookImport("sceGnmSubmitCommandBuffersForWorkload", &hkSceGnmSubmitCommandBuffersForWorkload)) |orig_fn|
        originalFuncs.gnmSubmitCommandBuffersForWorkload = @ptrCast(orig_fn)
    else |_| {}
    if (hookImport("sceGnmSubmitAndFlipCommandBuffers", &hkSceGnmSubmitAndFlipCommandBuffers)) |orig_fn|
        originalFuncs.gnmSubmitAndFlipCommandBuffers = @ptrCast(orig_fn)
    else |_| {}
    if (hookImport("sceGnmSubmitAndFlipCommandBuffersForWorkload", &hkSceGnmSubmitAndFlipCommandBuffersForWorkload)) |orig_fn|
        originalFuncs.gnmSubmitAndFlipCommandBuffersForWorkload = @ptrCast(orig_fn)
    else |_| {}
    if (hookImport("sceGnmRequestFlipAndSubmitDone", &hkSceGnmRequestFlipAndSubmitDone)) |orig_fn|
        originalFuncs.gnmRequestFlipAndSubmitDone = @ptrCast(orig_fn)
    else |_| {}
    if (hookImport("sceGnmRequestFlipAndSubmitDoneForWorkload", &hkSceGnmRequestFlipAndSubmitDoneForWorkload)) |orig_fn|
        originalFuncs.gnmRequestFlipAndSubmitDoneForWorkload = @ptrCast(orig_fn)
    else |_| {}

    log.info("gnmtrace: initialized", .{});
}

fn moduleStop() !void {
    if (tracer) |*t|
        t.deinit();
    us.terminate();
    threaded.deinit();
    debug_allocator.deinitWithoutLeakChecks();
}

fn hookImport(function_name: [:0]const u8, new_function: *const anyopaque) !*anyopaque {
    return mira.Substitute.hookIatByName(function_name, new_function, .{}) catch |err| {
        log.err("Couldn't hook {s} with {t}, quitting...", .{ function_name, err });
        return err;
    };
}

var originalFuncs: struct {
    videoOutOpen: ?*const fn (
        user_id: us.UserId,
        bus_type: vo.Bus,
        index: i32,
        param: ?*const anyopaque,
    ) callconv(.c) i32 = null,
    videoOutRegisterBuffers: ?*const fn (
        handle: vo.Display.Handle,
        start_index: i32,
        addresses: [*]const [*]const u8,
        num_buffers: i32,
        attribute: *const vo.BufferAttribute,
    ) callconv(.c) i32 = null,
    videoOutSubmitFlip: ?*const fn (
        handle: vo.Display.Handle,
        buffer_index: i32,
        flip_type: vo.FlipType,
        flip_arg: u64,
    ) callconv(.c) i32 = null,

    padOpen: ?*const fn (
        user_id: us.UserId,
        port_type: Pad.Controller.PortType,
        index: i32,
    ) callconv(.c) i32 = null,

    gnmSubmitDone: ?*const fn () callconv(.c) i32 = null,
    gnmSubmitCommandBuffers: ?*const fn (
        count: u32,
        dcb_addrs: ?[*]const [*]const u32,
        dcb_byte_sizes: ?[*]const u32,
        ccb_addrs: ?[*]const [*]u32,
        ccb_byte_sizes: ?[*]const u32,
    ) callconv(.c) i32 = null,
    gnmSubmitCommandBuffersForWorkload: ?*const fn (
        count: u32,
        dcb_addrs: ?[*]const [*]const u32,
        dcb_byte_sizes: ?[*]const u32,
        ccb_addrs: ?[*]const [*]u32,
        ccb_byte_sizes: ?[*]const u32,
    ) callconv(.c) i32 = null,
    gnmSubmitAndFlipCommandBuffers: ?*const fn (
        count: u32,
        dcb_addrs: ?[*]const [*]const u32,
        dcb_byte_sizes: ?[*]const u32,
        ccb_addrs: ?[*]const [*]u32,
        ccb_byte_sizes: ?[*]const u32,
        handle: vo.Display.Handle,
        buffer_index: i32,
        flip_type: vo.FlipType,
        flip_arg: u64,
    ) callconv(.c) i32 = null,
    gnmSubmitAndFlipCommandBuffersForWorkload: ?*const fn (
        count: u32,
        dcb_addrs: ?[*]const [*]const u32,
        dcb_byte_sizes: ?[*]const u32,
        ccb_addrs: ?[*]const [*]u32,
        ccb_byte_sizes: ?[*]const u32,
        handle: vo.Display.Handle,
        buffer_index: i32,
        flip_type: vo.FlipType,
        flip_arg: u64,
    ) callconv(.c) i32 = null,
    gnmRequestFlipAndSubmitDone: ?*const fn (
        gpu_addr: [*]u8,
        gpu_addr_len: u32,
        handle: vo.Display.Handle,
        buffer_index: i32,
        flip_type: vo.FlipType,
        flip_arg: u64,
    ) callconv(.c) i32 = null,
    gnmRequestFlipAndSubmitDoneForWorkload: ?*const fn (
        gpu_addr: [*]u8,
        gpu_addr_len: u32,
        handle: vo.Display.Handle,
        buffer_index: i32,
        flip_type: vo.FlipType,
        flip_arg: u64,
    ) callconv(.c) i32 = null,
} = .{};

fn shouldTrace() bool {
    if (my_pad) |muh_pad| {
        if (muh_pad.controller.readState()) |state| {
            return state.buttons.l1 and state.buttons.cross;
        } else |err| {
            log.err("Failed to get pad's state with {t}", .{err});
        }
    }
    return false;
}

//
// libSceVideoOut hooks
//
fn hkSceVideoOutOpen(user_id: us.UserId, bus_type: vo.Bus, index: i32, param: ?*const anyopaque) callconv(.c) i32 {
    if (tracer == null) {
        // HACK: the segfault handler can't be install at moduleStart,
        // so do it when the main module is ready and running
        std.debug.attachSegfaultHandler();

        log.info("Setting up frametracer...", .{});

        Pad.globalInit();
        log.info("Pad library initialized", .{});

        us.initialize(.{}) catch |err| {
            log.err("Failed to init UserService with {t}", .{err});
        };
        log.info("UserService library initialized", .{});

        if (us.getInitialUser()) |pad_user_id| {
            if (Pad.Controller.open(pad_user_id, .standard, 0)) |controller| {
                log.info("Opened controller handle {x}", .{controller.handle});
                my_pad = .{
                    .controller = controller,
                    .kind = .standard,
                    .owner_id = pad_user_id,
                    .index = 0,
                };
            } else |err| {
                log.warn("Failed to open controller with {t}, falling back to getting its handle...", .{err});
                if (Pad.Controller.getHandle(pad_user_id, .standard, 0)) |found_controller| {
                    log.info("Got controller handle {x}", .{found_controller.handle});
                    my_pad = .{
                        .controller = found_controller,
                        .kind = .standard,
                        .owner_id = pad_user_id,
                        .index = 0,
                    };
                } else |find_err| {
                    log.warn("Failed to get controller handle with {t}, INPUT UNAVAILABLE!", .{find_err});
                }
            }
        } else |err| {
            log.warn("Failed to get initial user ID with {t}, INPUT UNAVAILABLE!", .{err});
        }

        threaded = .init(allocator, .{});
        errdefer threaded.deinit();
        log.info("Threaded IO initialized", .{});

        const title_id = mem.sliceTo(&proc_info.?.title_id, 0);
        const process_name = mem.sliceTo(&proc_info.?.process_name, 0);
        if (Frametracer.init(threaded.io(), title_id, process_name)) |tr| {
            tracer = tr;
            log.info("Frametracer ready!", .{});
        } else |err| {
            log.err("Failed to init frame tracer with {t}", .{err});
        }
    }

    const result = originalFuncs.videoOutOpen.?(user_id, bus_type, index, param);

    if (result >= 0) {
        tracer.?.setVideoHandle(bus_type, result);
    }

    return result;
}

fn hkSceVideoOutRegisterBuffers(
    handle: vo.Display.Handle,
    start_index: i32,
    addresses: [*]const [*]const u8,
    num_buffers: i32,
    attribute: *const vo.BufferAttribute,
) callconv(.c) i32 {
    if (start_index >= 0 and num_buffers > 0) {
        const start_index_u32: u32 = @bitCast(start_index);
        const buf_count: u32 = @bitCast(num_buffers);
        tracer.?.setVideoBuffers(
            handle,
            @truncate(start_index_u32),
            addresses[0..buf_count],
            attribute.*,
        ) catch |err| {
            log.err("Failed to set video buffers with {t}", .{
                err,
            });
        };
    }

    return originalFuncs.videoOutRegisterBuffers.?(
        handle,
        start_index,
        addresses,
        num_buffers,
        attribute,
    );
}

fn hkSceVideoOutSubmitFlip(
    handle: vo.Display.Handle,
    buffer_index: i32,
    mode: vo.FlipType,
    user_data: u64,
) callconv(.c) i32 {
    const result = originalFuncs.videoOutSubmitFlip.?(
        handle,
        buffer_index,
        mode,
        user_data,
    );

    if (buffer_index >= 0) {
        const buffer_index_u32: u32 = @bitCast(buffer_index);
        tracer.?.onFlip(handle, @truncate(buffer_index_u32), mode, user_data) catch |err| {
            log.err("Failed to record display flip with {t}", .{
                err,
            });
        };
    }

    return result;
}

//
// Pad
//
fn hkScePadOpen(
    user_id: us.UserId,
    port_type: Pad.Controller.PortType,
    index: i32,
) callconv(.c) i32 {
    log.debug("PadOpen called for user 0x{x} port {t} and index {}", .{
        user_id,
        port_type,
        index,
    });

    // GR1 doesn't like when we ask ScePad for an already open controller,
    // so just check ours right away.
    if (my_pad) |muh_pad| {
        @branchHint(.likely);
        if (muh_pad.owner_id == user_id and muh_pad.kind == port_type and muh_pad.index == index) {
            @branchHint(.likely);

            log.debug("PadOpen wanted our controller {x}, returning it", .{muh_pad.controller.handle});
            return muh_pad.controller.handle;
        }
    }

    return originalFuncs.padOpen.?(user_id, port_type, index);
}

//
// libSceGnmDriver hooks
//
fn hkSceGnmSubmitDone() callconv(.c) i32 {
    const result = originalFuncs.gnmSubmitDone.?();

    tracer.?.end() catch |err| {
        log.err("Failed to end tracing with {t}", .{
            err,
        });
    };
    tracer.?.onSubmitDone();
    if (shouldTrace()) {
        tracer.?.begin() catch |err| {
            log.err("Failed to begin tracing with {t}", .{
                err,
            });
        };
    }

    return result;
}

fn hkSceGnmSubmitCommandBuffers(
    count: u32,
    maybe_dcb_addrs: ?[*]const [*]const u32,
    maybe_dcb_byte_sizes: ?[*]const u32,
    maybe_ccb_addrs: ?[*]const [*]u32,
    maybe_ccb_byte_sizes: ?[*]const u32,
) callconv(.c) i32 {
    if (maybe_dcb_addrs) |dcb_addrs| {
        if (maybe_dcb_byte_sizes) |dcb_byte_sizes| {
            tracer.?.processCommands(dcb_addrs[0..count], dcb_byte_sizes[0..count]) catch |err| {
                log.err("Failed to process commands with {t}", .{err});
            };
        }
    }

    const res = originalFuncs.gnmSubmitCommandBuffers.?(
        count,
        maybe_dcb_addrs,
        maybe_dcb_byte_sizes,
        maybe_ccb_addrs,
        maybe_ccb_byte_sizes,
    );
    return res;
}

fn hkSceGnmSubmitCommandBuffersForWorkload(
    count: u32,
    maybe_dcb_addrs: ?[*]const [*]const u32,
    maybe_dcb_byte_sizes: ?[*]const u32,
    maybe_ccb_addrs: ?[*]const [*]u32,
    maybe_ccb_byte_sizes: ?[*]const u32,
) callconv(.c) i32 {
    if (maybe_dcb_addrs) |dcb_addrs| {
        if (maybe_dcb_byte_sizes) |dcb_byte_sizes| {
            tracer.?.processCommands(dcb_addrs[0..count], dcb_byte_sizes[0..count]) catch |err| {
                log.err("Failed to process commands with {t}", .{err});
            };
        }
    }

    return originalFuncs.gnmSubmitCommandBuffersForWorkload.?(
        count,
        maybe_dcb_addrs,
        maybe_dcb_byte_sizes,
        maybe_ccb_addrs,
        maybe_ccb_byte_sizes,
    );
}

fn hkSceGnmSubmitAndFlipCommandBuffers(
    count: u32,
    maybe_dcb_addrs: ?[*]const [*]const u32,
    maybe_dcb_byte_sizes: ?[*]const u32,
    maybe_ccb_addrs: ?[*]const [*]u32,
    maybe_ccb_byte_sizes: ?[*]const u32,
    handle: vo.Display.Handle,
    buffer_index: i32,
    mode: vo.FlipType,
    user_data: u64,
) callconv(.c) i32 {
    if (maybe_dcb_addrs) |dcb_addrs| {
        if (maybe_dcb_byte_sizes) |dcb_byte_sizes| {
            tracer.?.processCommands(dcb_addrs[0..count], dcb_byte_sizes[0..count]) catch |err| {
                log.err("Failed to process commands with {t}", .{err});
            };
        }
    }

    const result = originalFuncs.gnmSubmitAndFlipCommandBuffers.?(
        count,
        maybe_dcb_addrs,
        maybe_dcb_byte_sizes,
        maybe_ccb_addrs,
        maybe_ccb_byte_sizes,
        handle,
        buffer_index,
        mode,
        user_data,
    );

    if (buffer_index >= 0) {
        const buffer_index_u32: u32 = @bitCast(buffer_index);
        tracer.?.onFlip(handle, @truncate(buffer_index_u32), mode, user_data) catch |err| {
            log.err("Failed to record display flip with {t}", .{
                err,
            });
        };
    }

    return result;
}

fn hkSceGnmSubmitAndFlipCommandBuffersForWorkload(
    count: u32,
    maybe_dcb_addrs: ?[*]const [*]const u32,
    maybe_dcb_byte_sizes: ?[*]const u32,
    maybe_ccb_addrs: ?[*]const [*]u32,
    maybe_ccb_byte_sizes: ?[*]const u32,
    handle: vo.Display.Handle,
    buffer_index: i32,
    mode: vo.FlipType,
    user_data: u64,
) callconv(.c) i32 {
    if (maybe_dcb_addrs) |dcb_addrs| {
        if (maybe_dcb_byte_sizes) |dcb_byte_sizes| {
            tracer.?.processCommands(dcb_addrs[0..count], dcb_byte_sizes[0..count]) catch |err| {
                log.err("Failed to process commands with {t}", .{err});
            };
        }
    }

    const result = originalFuncs.gnmSubmitAndFlipCommandBuffersForWorkload.?(
        count,
        maybe_dcb_addrs,
        maybe_dcb_byte_sizes,
        maybe_ccb_addrs,
        maybe_ccb_byte_sizes,
        handle,
        buffer_index,
        mode,
        user_data,
    );

    if (buffer_index >= 0) {
        const buffer_index_u32: u32 = @bitCast(buffer_index);
        tracer.?.onFlip(handle, @truncate(buffer_index_u32), mode, user_data) catch |err| {
            log.err("Failed to record display flip with {t}", .{
                err,
            });
        };
    }

    return result;
}

fn hkSceGnmRequestFlipAndSubmitDone(
    gpu_addr: [*]u8,
    gpu_addr_len: u32,
    handle: vo.Display.Handle,
    buffer_index: i32,
    mode: vo.FlipType,
    user_data: u64,
) callconv(.c) i32 {
    const buffer_index_u32: u32 = @bitCast(buffer_index);
    tracer.?.onFlip(handle, @truncate(buffer_index_u32), mode, user_data) catch |err| {
        log.err("Failed to record display flip with {t}", .{
            err,
        });
    };

    const result = originalFuncs.gnmRequestFlipAndSubmitDone.?(
        gpu_addr,
        gpu_addr_len,
        handle,
        buffer_index,
        mode,
        user_data,
    );

    tracer.?.end() catch |err| {
        log.err("Failed to end tracing with {t}", .{
            err,
        });
    };
    tracer.?.onSubmitDone();
    if (shouldTrace()) {
        tracer.?.begin() catch |err| {
            log.err("Failed to begin tracing with {t}", .{
                err,
            });
        };
    }

    return result;
}

fn hkSceGnmRequestFlipAndSubmitDoneForWorkload(
    gpu_addr: [*]u8,
    gpu_addr_len: u32,
    handle: vo.Display.Handle,
    buffer_index: i32,
    mode: vo.FlipType,
    user_data: u64,
) callconv(.c) i32 {
    const buffer_index_u32: u32 = @bitCast(buffer_index);
    tracer.?.onFlip(handle, @truncate(buffer_index_u32), mode, user_data) catch |err| {
        log.err("Failed to record display flip with {t}", .{
            err,
        });
    };

    const result = originalFuncs.gnmRequestFlipAndSubmitDoneForWorkload.?(
        gpu_addr,
        gpu_addr_len,
        handle,
        buffer_index,
        mode,
        user_data,
    );

    tracer.?.end() catch |err| {
        log.err("Failed to end tracing with {t}", .{
            err,
        });
    };
    tracer.?.onSubmitDone();
    if (shouldTrace()) {
        tracer.?.begin() catch |err| {
            log.err("Failed to begin tracing with {t}", .{
                err,
            });
        };
    }

    return result;
}

// HACK: some code in freegnm is unfortunatelly calling this
// TODO: replace it then get rid of this
// export fn __assert_fail(
//     expr: [*:0]const u8,
//     file: [*:0]const u8,
//     line: c_int,
//     func: [*:0]const u8,
// ) callconv(.c) noreturn {
//     log.err("Assertion failed: {s} ({s}: {s}: {})", .{ expr, file, func, line });
//     std.process.abort();
// }
