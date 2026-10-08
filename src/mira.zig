const std = @import("std");
const ps4 = std.os.ps4;
const assert = std.debug.assert;

const orbis = @import("orbis");
const Kernel = orbis.Kernel;

pub fn ownProcessInfo() !ProcessInfo {
    const fd = try Kernel.fileOpenAbsolute(MIRA_PATH, .{ .ACCMODE = .RDWR }, 0);
    defer Kernel.fileClose(fd);

    var info: ProcessInfo = .empty;
    const result = ps4.ioctl(fd, @bitCast(IoCtl.GET_PROC_INFO), &info);

    if (result != 0)
        return error.IoCtlFailed;
    return info;
}

pub fn getThreadInfo(
    threads_buffer: []Thread,
    options: struct { pid: ?ps4.pid_t = null },
) !ThreadInfo {
    const fd = try Kernel.fileOpenAbsolute(MIRA_PATH, .{ .ACCMODE = .RDWR }, 0);
    defer Kernel.fileClose(fd);

    var info = ThreadInfo{
        .pid = options.pid orelse 0,
        .max_threads_count = @truncate(threads_buffer.len),
        .threads_buf = threads_buffer.ptr,
    };
    const result = ps4.ioctl(fd, @bitCast(IoCtl.GET_THRD_INFO), &info);
    if (result != 0)
        return error.IoCtlFailed;
    return info;
}

pub fn escapePrison() !PrisonInfo {
    const fd = try Kernel.fileOpenAbsolute(MIRA_PATH, .{ .ACCMODE = .RDWR }, 0);
    defer Kernel.fileClose(fd);

    var old_prison: PrisonInfo = .empty;
    const result = ps4.ioctl(fd, @bitCast(IoCtl.ESCAPE_PRISON), &old_prison);
    if (result != 0)
        return error.IoCtlFailed;
    return old_prison;
}

pub fn returnPrison(target_prison: PrisonInfo) !void {
    const fd = try Kernel.fileOpenAbsolute(MIRA_PATH, .{ .ACCMODE = .RDWR }, 0);
    defer Kernel.fileClose(fd);

    const result = ps4.ioctl(fd, @bitCast(IoCtl.RETURN_PRISON), &target_prison);
    if (result != 0)
        return error.IoCtlFailed;
}

pub const ProcessInfo = extern struct {
    process_base_address: ?*anyopaque,
    pid: i32,
    op_pid: i32,
    debug_child: i32,
    exit_threads: i32,
    sig_parent: i32,
    signal: i32,
    code: u32,
    stops: u32,
    s_type: u32,
    process_name: [31:0]u8,
    title_id: [15:0]u8,
    content_id: [63:0]u8,
    randomized_path: [255:0]u8,
    elf_path: [1023:0]u8,

    pub const empty: ProcessInfo = .{
        .process_base_address = null,
        .pid = 0,
        .op_pid = 0,
        .debug_child = 0,
        .exit_threads = 0,
        .sig_parent = 0,
        .signal = 0,
        .code = 0,
        .stops = 0,
        .s_type = 0,
        .process_name = @splat(0),
        .title_id = @splat(0),
        .content_id = @splat(0),
        .randomized_path = @splat(0),
        .elf_path = @splat(0),
    };
};

const Thread = extern struct {
    tid: i32,
    err_no: i32,
    ret_val: i64,
    name: [36:0]u8,
};

const ThreadInfo = extern struct {
    // inputs
    pid: ps4.pid_t,
    max_threads_count: u32,
    // outputs
    num_threads: u32 = 0,
    actual_num_threads: u32 = 0,
    // user provided buffer
    threads_buf: [*]Thread,
};

pub const PrisonInfo = extern struct {
    prison: u64,
    auth_id: u64,
    caps_0: u64,

    pub const empty: PrisonInfo = .{
        .prison = 0,
        .auth_id = 0,
        .caps_0 = 0,
    };
};

pub const Substitute = struct {
    pub const HookIatByNameOptions = struct {
        module_name: ?[:0]const u8 = null,
    };

    pub fn hookIatByName(
        function_name: [:0]const u8,
        new_function: *const anyopaque,
        options: HookIatByNameOptions,
    ) !*anyopaque {
        const fd = try Kernel.fileOpenAbsolute(MIRA_PATH, .{ .ACCMODE = .RDWR }, 0);
        defer Kernel.fileClose(fd);

        var chain = UatHook{
            .hook_id = 0,
            .hook_function = null,
            .original_function = null,
            .next = null,
        };
        var iat = IatHook{
            .hook_id = 0,
            .flags = .hook_by_name,
            .hook_function = new_function,
            .chain = &chain,
            .name = undefined,
            .module_name = undefined,
        };

        iat.name[function_name.len] = 0;
        @memcpy(iat.name[0..function_name.len], function_name);

        if (options.module_name) |mod_name| {
            iat.module_name[mod_name.len] = 0;
            @memcpy(iat.module_name[0..mod_name.len], mod_name);
        } else {
            iat.module_name[0] = 0;
        }

        const result = ps4.ioctl(fd, @bitCast(IoCtl.HOOK_IAT), &iat);
        if (result != 0)
            return error.IoCtlFailed;

        if (chain.original_function) |orig_fn|
            return orig_fn
        else
            return error.HookFailed;
    }

    const UatHook = extern struct {
        hook_id: i32,
        _: i32 = 0,
        hook_function: ?*anyopaque,
        original_function: ?*anyopaque,
        next: ?*UatHook,
    };

    const IatHook = extern struct {
        const Flags = enum(i32) {
            hook_by_name = 0,
            hook_by_nid = 1,
        };

        hook_id: i32,
        flags: Flags,
        hook_function: ?*const anyopaque,
        chain: ?*UatHook,
        name: [255:0]u8,
        module_name: [255:0]u8,
    };
};

comptime {
    assert(@sizeOf(ProcessInfo) == 0x5a0);
    assert(@sizeOf(Thread) == 0x38);
    assert(@sizeOf(ThreadInfo) == 0x18);
    assert(@offsetOf(Substitute.IatHook, "hook_function") == 0x8);
    assert(@offsetOf(Substitute.IatHook, "chain") == 0x10);
    assert(@offsetOf(Substitute.IatHook, "name") == 0x18);
    assert(@sizeOf(Substitute.UatHook) == 0x20);
    assert(@sizeOf(Substitute.IatHook) == 0x218);
}

const MIRA_PATH = "/dev/mira";
const MIRA_IOCTL_BASE = 'M';
const SUBSTITUTE_IOCTL_BASE = 'S';

const IoCtl = struct {
    const Request = packed struct(u32) {
        num: u8,
        group: u8,
        len: u13,
        param: packed struct(u3) {
            void: bool = false,
            out: bool = false,
            in: bool = false,
        },
    };
    const GET_PROC_INFO = Request{
        .num = 3,
        .group = MIRA_IOCTL_BASE,
        .len = @sizeOf(ProcessInfo),
        .param = .{
            .in = true,
            .out = true,
        },
    };
    const GET_THRD_INFO = Request{
        .num = 7,
        .group = MIRA_IOCTL_BASE,
        .len = @sizeOf(ThreadInfo),
        .param = .{
            .in = true,
            .out = true,
        },
    };
    const ESCAPE_PRISON = Request{
        .num = 8,
        .group = MIRA_IOCTL_BASE,
        .len = @sizeOf(PrisonInfo),
        .param = .{
            .out = true,
        },
    };

    const RETURN_PRISON = Request{
        .num = 9,
        .group = MIRA_IOCTL_BASE,
        .len = @sizeOf(PrisonInfo),
        .param = .{
            .in = true,
        },
    };
    const HOOK_IAT = Request{
        .num = 1,
        .group = SUBSTITUTE_IOCTL_BASE,
        .len = @sizeOf(Substitute.IatHook),
        .param = .{
            .in = true,
            .out = true,
        },
    };
};

comptime {
    assert(@as(u32, @bitCast(IoCtl.GET_PROC_INFO)) == 0xc5a04d03);
    assert(@as(u32, @bitCast(IoCtl.GET_THRD_INFO)) == 0xc0184d07);
    assert(@as(u32, @bitCast(IoCtl.ESCAPE_PRISON)) == 0x40184d08);
    assert(@as(u32, @bitCast(IoCtl.RETURN_PRISON)) == 0x80184d09);
    assert(@as(u32, @bitCast(IoCtl.HOOK_IAT)) == 0xc2185301);
}
