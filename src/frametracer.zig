const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const Io = std.Io;
const log = std.log.scoped(.tracer);
const mem = std.mem;
const meta = std.meta;
const ps4 = std.os.ps4;
const tar = std.tar;
const time = std.time;
const zon = std.zon;
const ArrayList = std.ArrayList;
const Thread = std.Thread;

const orbis = @import("orbis");
const Kernel = orbis.Kernel;
const vo = orbis.VideoOut;
const orbis_page_size = orbis.Kernel.page_size_default;

const gnm = @import("gnm");
const gcn = gnm.gcn;
const pm4 = gnm.pm4;

const lz4u = @import("lz4u");
const mira = @import("mira.zig");

const DATA_DIR_PATH = "/data/gnmtrace";
const TARGET_BMS: lz4u.Frame.BlockMaxSize = .@"4MB";

const Frametracer = @This();

io: Io,

title_id: []const u8,
process_name: []const u8,

active_data: ?struct {
    file: ps4.fd_t,
    now: Io.Timestamp,
},
active_lock: Io.Mutex,

cur_frame_index: usize,
cur_cmd_index: u32,

perma_arena: heap.ArenaAllocator,
trace_arena: heap.ArenaAllocator,
analyzer_arena: heap.ArenaAllocator,

display_handles: struct {
    main: ?vo.Display.Handle,
    aux_social: ?vo.Display.Handle,
    aux_stream: ?vo.Display.Handle,

    fn findBusType(self: @This(), display_handle: vo.Display.Handle) ?vo.Bus {
        return if (display_handle == self.main)
            .Main
        else if (display_handle == self.aux_social)
            .Social
        else if (display_handle == self.aux_stream)
            .Live
        else
            null;
    }
},

memory_regions: ArrayList(MemoryRegion),
flip_list: ArrayList(Flip),
command_buffers: ArrayList(CommandBuffer),
registered_display_buffers: ArrayList(DisplayBuffer),

const MemoryRegion = struct {
    virtual_start: u56,
    virtual_end: u56,
    physical_addr: u56,
    protection: Kernel.PROT,
    mem_type: Kernel.MemoryType,
    name: [32:0]u8,
};

const MemoryRange = struct {
    ptr: u56,
    len: u56,

    fn toSlice(self: MemoryRange) []const u8 {
        const ptr_u8: [*]const u8 = @ptrFromInt(self.ptr);
        return ptr_u8[0..self.len];
    }

    fn fromSlice(data: []const u8) MemoryRange {
        return .{
            .ptr = @intCast(@intFromPtr(data.ptr)),
            .len = @intCast(data.len),
        };
    }
};

const Flip = struct {
    memory: MemoryRange,
    after_cmd_index: u32,
    bus: vo.Bus,
    buffer_index: u32,
    mode: vo.FlipType,
    user_data: u64,
};

const CommandBuffer = struct {
    region: MemoryRange,
};

const VideoHandle = struct {
    handle: vo.Display.Handle,
    bus: vo.Bus,
};

const DisplayBuffer = struct {
    bus: vo.Bus,
    index: u32,

    backing_memory: MemoryRange,
    attribute: Attribute,

    const Attribute = extern struct {
        pixel_format: vo.PixelFormat,
        tiling_mode: vo.TilingMode,
        aspect_ratio: vo.AspectRatio,
        width: u32,
        height: u32,
        pitch_in_pixel: u32,
        option: vo.BufferAttribute.Option,
    };
};

pub fn init(io: Io, title_id: []const u8, process_name: []const u8) !Frametracer {
    Kernel.createDirAbsolute(DATA_DIR_PATH, 0) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            log.err("Failed to create data directory at {s} with {t}", .{ DATA_DIR_PATH, err });
            return err;
        },
    };

    const res: Frametracer = .{
        .io = io,

        .title_id = title_id,
        .process_name = process_name,
        .active_data = null,
        .active_lock = .init,
        .cur_frame_index = 0,
        .cur_cmd_index = 0,

        .perma_arena = .init(heap.page_allocator),
        .trace_arena = .init(heap.page_allocator),
        .analyzer_arena = .init(heap.page_allocator),

        .display_handles = .{
            .main = null,
            .aux_social = null,
            .aux_stream = null,
        },
        .memory_regions = .empty,
        .flip_list = .empty,
        .command_buffers = .empty,
        .registered_display_buffers = .empty,
    };
    return res;
}

pub fn deinit(self: *Frametracer) void {
    if (self.active_data) |*ad| {
        Kernel.fileClose(ad.file);
    }
    self.perma_arena.deinit();
    self.trace_arena.deinit();
    self.analyzer_arena.deinit();
}

pub fn begin(self: *Frametracer) !void {
    self.active_lock.lockUncancelable(self.io);
    defer self.active_lock.unlock(self.io);

    if (self.active_data != null)
        return error.AlreadyTracing;

    const now = Io.Clock.now(.real, self.io);
    const epoch_secs = time.epoch.EpochSeconds{ .secs = @intCast(now.toSeconds()) };
    const epoch_ds = epoch_secs.getDaySeconds();
    const epoch_days = epoch_secs.getEpochDay();
    const epoch_yd = epoch_days.calculateYearDay();
    const epoch_md = epoch_yd.calculateMonthDay();

    var file_path_buf: [256]u8 = undefined;
    const file_path = try mem.printSentinel(
        &file_path_buf,
        DATA_DIR_PATH ++ "/{s}-{s}_{}_{:0>2}.{:0>2}.{:0>2}_{:0>2}.{:0>2}.tar.lz4",
        .{
            self.title_id,
            self.process_name,
            self.cur_frame_index,
            epoch_yd.year,
            epoch_md.month.numeric(),
            epoch_md.day_index + 1,
            epoch_ds.getHoursIntoDay(),
            epoch_ds.getMinutesIntoHour(),
        },
        0,
    );

    log.info("Creating frame trace at {s}", .{file_path});

    const trace_file = res: {
        const temp_caps: ?Jailbreak = Jailbreak.obtain() catch |err| caps: {
            log.err("Failed to set ucred's capabilities to ALL with {t}", .{err});
            break :caps null;
        };
        defer {
            if (temp_caps) |caps| caps.restore() catch |err| {
                log.err("Failed to restore old ucred's capabilities with {t}", .{err});
            };
        }
        break :res Kernel.fileOpenAbsolute(file_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0) catch |err| {
            log.err("Failed to create archive at {s} with {t}", .{ file_path, err });
            return err;
        };
    };
    errdefer trace_file.close();

    self.active_data = .{
        .file = trace_file,
        .now = now,
    };
    self.cur_cmd_index = 0;
}

fn dumpMemory(self: *Frametracer, data: []const u8, caller: std.builtin.SourceLocation) !void {
    _ = caller;
    const addr: u56 = @intCast(@intFromPtr(data.ptr));

    // calculate the page(s) start and end
    const region_start = mem.alignBackward(u56, addr, orbis_page_size);
    const start_len: u56 = @intCast(data.len + (addr - region_start));

    const region_info = try Kernel.virtualQueryInfo(@ptrFromInt(region_start));

    const aligned_len = mem.alignForward(u56, start_len, orbis_page_size);
    const region_end = @min(region_start + aligned_len, region_info.virtual_end);

    // find any existing region and reuse, expanding it if necessary
    for (self.memory_regions.items) |*entry| {
        if (entry.virtual_start == region_start) {
            // log.info("dumpMemory: reusing region {x}-{x} -> {x}-{x} aligned len {x} caller {s} {}", .{
            //     @intFromPtr(data.ptr),
            //     @intFromPtr(data.ptr) + data.len,
            //     entry.ptr,
            //     entry.ptr + entry.len,
            //     aligned_len,
            //     caller.fn_name,
            //     caller.line,
            // });

            entry.virtual_end = @max(entry.virtual_end, region_end);
            return;
        }
    }

    // log.info("dumpMemory: new region {x}-{x} aligned region {x} aligned len {x} caller {s} {}", .{
    //     @intFromPtr(data.ptr),
    //     @intFromPtr(data.ptr) + data.len,
    //     region_start,
    //     aligned_len,
    //     caller.fn_name,
    //     caller.line,
    // });

    try self.memory_regions.append(self.trace_arena.allocator(), MemoryRegion{
        .virtual_start = region_start,
        .virtual_end = region_end,
        .physical_addr = @intCast(region_info.physical_address),
        .protection = region_info.protection,
        .mem_type = region_info.memory_type,
        .name = region_info.name,
    });
}

pub fn end(self: *Frametracer) !void {
    self.active_lock.lockUncancelable(self.io);
    defer self.active_lock.unlock(self.io);

    // clear everything regardless of success
    defer ({
        if (self.active_data) |*ad| {
            Kernel.fileClose(ad.file);
            self.active_data = null;
        }
        self.memory_regions = .empty;
        self.flip_list = .empty;
        self.command_buffers = .empty;
        _ = self.trace_arena.reset(.retain_capacity);
    });

    const active_data = self.active_data orelse
        return;

    const total_regions_len = res: {
        var count: u64 = 0;
        for (self.memory_regions.items) |entry| {
            const length = entry.virtual_end - entry.virtual_start;
            count += length;
        }
        break :res count;
    };

    log.info("Writing {B} (0x{x} bytes) in {} memory regions, {} flips and {} command buffers for frame {}", .{
        total_regions_len,
        total_regions_len,
        self.memory_regions.items.len,
        self.flip_list.items.len,
        self.command_buffers.items.len,
        self.cur_frame_index,
    });

    const trace_alloc = self.trace_arena.allocator();

    const file_writer_buf = try trace_alloc.alloc(u8, TARGET_BMS.toBytes() + lz4u.max_window_len);
    const file: Io.File = .{
        .handle = active_data.file,
        .flags = .{ .nonblocking = false },
    };
    var file_writer = file.writer(self.io, file_writer_buf);

    const compress_buffer = try trace_alloc.alloc(u8, lz4u.min_indirect_buffer_len);
    var compressor: lz4u.Frame.Compress = try .init(&file_writer.interface, compress_buffer, .{
        .max_block_size = TARGET_BMS,
        .should_checksum_frame = true,
        .should_checksum_block = true,
        .independent_blocks = false,
    });
    var archive_writer = tar.Writer{ .underlying_writer = &compressor.writer };

    const report = .{
        .title_id = self.title_id,
        .process_name = self.process_name,
        .frame = self.cur_frame_index,
        .command_buffers = self.command_buffers.items,
        .display_buffers = self.registered_display_buffers.items,
        .flips = self.flip_list.items,
        .memory_regions = self.memory_regions.items,
    };

    var report_writer: Io.Writer.Allocating = .init(trace_alloc);

    try zon.stringify.serialize(report, .{}, &report_writer.writer);
    const report_data = try report_writer.toOwnedSlice();

    try archive_writer.writeFileBytes("report.zon", report_data, .{
        .mode = 0o644,
        .mtime = @intCast(active_data.now.toSeconds()),
    });

    for (self.memory_regions.items) |reg| {
        var memory_path_buf: [64]u8 = undefined;
        const memory_path = try fmt.bufPrint(&memory_path_buf, "memory/{x:0>8}", .{
            reg.virtual_start,
        });

        const length = reg.virtual_end - reg.virtual_start;
        const data_ptr: [*]align(orbis_page_size) u8 = @ptrFromInt(reg.virtual_start);
        const data = data_ptr[0..length];

        try archive_writer.writeFileBytes(memory_path, data, .{
            .mode = 0o644,
            .mtime = @intCast(active_data.now.toSeconds()),
        });
    }

    compressor.finish() catch |err| {
        log.err("Failed to finish compressed file with {t}", .{err});
        return;
    };
    file_writer.interface.flush() catch |err| {
        log.err("Failed to flush file with {t}", .{err});
        return;
    };

    log.info("Frame {} traced successfully", .{self.cur_frame_index});
}

pub fn onSubmitDone(self: *Frametracer) void {
    self.active_lock.lockUncancelable(self.io);
    defer self.active_lock.unlock(self.io);

    self.cur_frame_index += 1;
}

pub fn setVideoHandle(
    self: *Frametracer,
    bus_type: vo.Bus,
    handle: vo.Display.Handle,
) void {
    self.active_lock.lockUncancelable(self.io);
    defer self.active_lock.unlock(self.io);

    switch (bus_type) {
        .Main => self.display_handles.main = handle,
        .Social => self.display_handles.aux_social = handle,
        .Live => self.display_handles.aux_stream = handle,
    }
}

pub fn setVideoBuffers(
    self: *Frametracer,
    display_handle: vo.Display.Handle,
    start_index: u31,
    buffers: []const [*]const u8,
    attribute: vo.BufferAttribute,
) !void {
    self.active_lock.lockUncancelable(self.io);
    defer self.active_lock.unlock(self.io);

    const bus_type = self.display_handles.findBusType(display_handle) orelse
        return error.InvalidDisplayHandle;

    for (buffers, 0..) |buf, i| {
        // create a render target from the video buffer attributes so we can calculate its buffer byte length
        const rt = try gnm.RenderTarget.create(.{
            .format = switch (attribute.pixel_format) {
                .a8r8g8b8_srgb => .a8r8g8b8_srgb,
                .a8b8g8r8_srgb => .a8b8g8r8_srgb,
                .a16r16g16b16_float => .a16b16g16r16_float,
                .a2r10g10b10,
                .a2r10g10b10_bt2020_pq,
                => .a2b10g10r10_float,
                .a2r10g10b10_srgb => .a2b10g10r10_srgb,
            },
            .width = attribute.width,
            .height = attribute.height,
            .pitch = attribute.pitch_in_pixel,
            .num_slices = 1,
            .num_samples = 1,
            .num_fragments = 1,

            .tile_mode_hint = switch (attribute.tiling_mode) {
                .tiled => .display_2d_thin,
                .linear => .display_linear_aligned,
            },
            .min_gpu_mode = .base, // TODO: get current mode
        });

        const size = try rt.calcByteSize();
        const cur_index = start_index + @as(u32, @intCast(i));

        const new_display_buf: DisplayBuffer = .{
            .bus = bus_type,
            .index = cur_index,
            .backing_memory = .{
                .ptr = @intCast(@intFromPtr(buf)),
                .len = @intCast(size.length),
            },
            .attribute = .{
                .pixel_format = attribute.pixel_format,
                .tiling_mode = attribute.tiling_mode,
                .aspect_ratio = attribute.aspect_ratio,
                .width = attribute.width,
                .height = attribute.height,
                .pitch_in_pixel = attribute.pitch_in_pixel,
                .option = attribute.option,
            },
        };

        // reuse any existing display buffer at the same bus and index
        const found_entry = res: for (self.registered_display_buffers.items) |*reg_buf| {
            if (reg_buf.bus == bus_type and reg_buf.index == cur_index) {
                break :res reg_buf;
            }
        } else null;

        if (found_entry) |entry| {
            entry.* = new_display_buf;
        } else {
            try self.registered_display_buffers.append(self.perma_arena.allocator(), new_display_buf);
        }
    }
}

pub fn onFlip(
    self: *Frametracer,
    display_handle: vo.Display.Handle,
    buffer_index: u31,
    mode: vo.FlipType,
    user_data: u64,
) !void {
    self.active_lock.lockUncancelable(self.io);
    defer self.active_lock.unlock(self.io);

    if (self.active_data == null)
        return;

    const bus_type = self.display_handles.findBusType(display_handle) orelse
        return error.InvalidDisplayHandle;

    const target_buf = res: for (self.registered_display_buffers.items) |db| {
        if (db.bus == bus_type and db.index == buffer_index) {
            break :res db;
        }
    } else return error.BufferNotFound;

    const data = target_buf.backing_memory.toSlice();

    try self.dumpMemory(data, @src());
    try self.flip_list.append(self.trace_arena.allocator(), .{
        .memory = target_buf.backing_memory,
        .after_cmd_index = self.cur_cmd_index,
        .bus = bus_type,
        .buffer_index = buffer_index,
        .mode = mode,
        .user_data = user_data,
    });
}

pub fn processCommands(
    self: *Frametracer,
    dcb_addresses: []const [*]const u32,
    dcb_byte_lengths: []const u32,
) !void {
    self.active_lock.lockUncancelable(self.io);
    defer self.active_lock.unlock(self.io);

    if (self.active_data == null)
        return;

    for (dcb_addresses, dcb_byte_lengths) |dcb_addr, dcb_byte_len| {
        const num_dwords = dcb_byte_len / @sizeOf(u32);
        const dcb = dcb_addr[0..num_dwords];

        var parser = pm4.Parser.init(dcb);
        var ctx: ParserContext = .empty;

        while (try parser.nextPacket()) |pkt| {
            const pkt_byte_off = parser.offset * @sizeOf(u32);
            switch (pkt.header.type) {
                else => |pkt_type| log.warn("Unparsed packet type {t}!", .{pkt_type}), // TODO?
                .pkt3 => self.parsePkt3(&ctx, pkt) catch |err| {
                    log.err("Failed to parse Pkt3 at word {} (byte offset 0x{x}) with {t}", .{
                        parser.offset,
                        pkt_byte_off,
                        err,
                    });
                },
            }
        }

        log.info("Dumping Command Buffer ptr {*} len 0x{x}", .{ dcb.ptr, dcb_byte_len });

        try self.command_buffers.append(self.trace_arena.allocator(), .{
            .region = .{
                .ptr = @intCast(@intFromPtr(dcb.ptr)),
                .len = @intCast(dcb_byte_len),
            },
        });
        try self.dumpMemory(@ptrCast(dcb), @src());

        self.cur_cmd_index += 1;
    }
}

pub fn parsePkt3(
    self: *Frametracer,
    ctx: *ParserContext,
    pkt: pm4.Parser.Packet,
) !void {
    switch (pkt.header.info.pkt3.it_opcode) {
        else => {},
        .index_base => {
            const addr_lo: u64 = try pkt.readDword(1);
            const addr_hi: u64 = try pkt.readDword(2);
            ctx.index_buffer = @ptrFromInt(addr_lo | (addr_hi << 32));
        },
        .index_buffer_size => ctx.index_count = try pkt.readDword(1),
        .index_type => {
            const value = try pkt.readDword(1);
            ctx.index_elem_size = switch (value) {
                else => return error.UnknownIndexType,
                0 => .@"16",
                1 => .@"32",
                2 => .@"8",
            };
        },
        .draw_index_2 => {
            const index_addr_lo: u64 = try pkt.readDword(2);
            const index_addr_hi: u64 = try pkt.readDword(3);

            if (index_addr_lo != 0 or index_addr_hi != 0) {
                const index_addr: [*]const u8 = @ptrFromInt(index_addr_lo | (index_addr_hi << 32));
                const buf_len = try pkt.readDword(1);
                const index_buf = index_addr[0..buf_len];

                try self.dumpMemory(index_buf, @src());
            } else {
                log.warn("Found a draw index packet without an index buffer!", .{});
            }

            try self.onGraphicsDraw(ctx);
        },
        .draw_index_auto => {
            try self.onGraphicsDraw(ctx);
        },
        .draw_index_offset_2 => {
            const max_count = try pkt.readDword(1);
            // const offset = try pkt.readDword(2);
            // const count = try pkt.readDword(3);

            if (ctx.index_buffer) |ib| {
                const index_byte_len = toIndexByteLen(ctx.index_elem_size);
                const max_byte_len: usize = max_count * index_byte_len;

                const cur_buf = ib[0..max_byte_len];
                try self.dumpMemory(cur_buf, @src());
            } else {
                log.warn("Found a draw index offset packet, but no index buffer is bound!", .{});
            }

            try self.onGraphicsDraw(ctx);
        },
        .draw_indirect,
        .draw_index_indirect,
        => |op| {
            if (op == .draw_index_indirect) {
                if (ctx.index_buffer) |ib| {
                    const byte_len = ctx.index_count * toIndexByteLen(ctx.index_elem_size);
                    const index_buf = ib[0..byte_len];
                    try self.dumpMemory(index_buf, @src());
                }
            }

            if (ctx.indirect_buffer) |indb| {
                const indirect_offset = try pkt.readDword(1);
                const buf_len: u5 = if (op == .draw_index_indirect)
                    @sizeOf(gnm.DrawIndexIndirectArgs)
                else if (op == .draw_indirect)
                    @sizeOf(gnm.DrawIndirectArgs)
                else
                    unreachable;

                const indirect_buf = indb[indirect_offset .. indirect_offset + buf_len];
                try self.dumpMemory(indirect_buf, @src());
            } else {
                log.warn("Found a draw indirect packet, but no indirect buffer is bound!", .{});
            }

            try self.onGraphicsDraw(ctx);
        },
        .wait_reg_mem => {
            const addr_lo = try pkt.readDword(2);
            const addr_hi: u64 = try pkt.readDword(3);
            if (addr_lo != 0 or addr_hi != 0) {
                const addr: [*]const u8 = @ptrFromInt(addr_lo | (addr_hi << 32));
                const buf = addr[0..@sizeOf(u32)];

                try self.dumpMemory(buf, @src());
            } else {
                log.warn("Found a wait reg mem packet without an address!", .{});
            }
        },
        .event_write_eop => {
            const wrm = try pkt.readStruct(0, gnm.DrawCommandBuffer.CmdEventWriteEop);
            const addr_lo = wrm.address_lo;
            const addr_hi: u64 = wrm.flags2.address_hi;

            if (addr_lo != 0 or addr_hi != 0) {
                const data_sel = wrm.flags2.data_sel;
                const maybe_byte_len: ?u3 = switch (data_sel) {
                    .discard => null,
                    .send_data_32 => @sizeOf(u32),
                    .send_data_64,
                    .send_sys_clock,
                    .send_gpu_clock,
                    => @sizeOf(u32),
                };

                if (maybe_byte_len) |byte_len| {
                    const addr: [*]const u8 = @ptrFromInt(addr_lo | (addr_hi << 32));
                    const buf = addr[0..byte_len];
                    try self.dumpMemory(buf, @src());
                } else {
                    log.warn("Found a event write EOP without memory!", .{});
                }
            }
        },
        .event_write_eos => {
            const wrm = try pkt.readStruct(0, gnm.DrawCommandBuffer.CmdEventWriteEos);
            const addr_lo = wrm.address_lo;
            const addr_hi: u64 = wrm.flags2.address_hi;

            if (addr_lo != 0 or addr_hi != 0) {
                const addr: [*]const u8 = @ptrFromInt(addr_lo | (addr_hi << 32));
                const buf = addr[0..@sizeOf(u32)];
                try self.dumpMemory(buf, @src());
            } else {
                log.warn("Found a event write EOS without an address!", .{});
            }
        },
        .dma_data => {
            const dma = try pkt.readStruct(0, gnm.DrawCommandBuffer.CmdDmaData);
            const src_addr_lo = dma.src_addr_lo;
            const src_addr_hi: u64 = dma.src_addr_hi;
            const dst_addr_lo = dma.dst_addr_lo;
            const dst_addr_hi: u64 = dma.dst_addr_hi;
            const byte_len = dma.command.byte_count;

            if (dma.command.src_addr_space == .memory and dma.flags.src_sel.isAddress()) {
                if (src_addr_lo != 0 or src_addr_hi != 0) {
                    const addr: [*]const u8 = @ptrFromInt(src_addr_lo | (src_addr_hi << 32));
                    const buf = addr[0..byte_len];
                    try self.dumpMemory(buf, @src());
                } else {
                    log.warn("Found a src address in DMA data packet without an address!", .{});
                }
            }
            if (dma.command.dst_addr_space == .memory and dma.flags.dst_sel.isAddress()) {
                if (dst_addr_lo != 0 or dst_addr_hi != 0) {
                    const addr: [*]const u8 = @ptrFromInt(dst_addr_lo | (dst_addr_hi << 32));
                    const buf = addr[0..byte_len];
                    try self.dumpMemory(buf, @src());
                } else {
                    log.warn("Found a dst address in DMA data packet without an address!", .{});
                }
            }
        },
        .acquire_mem => {
            const aqm = try pkt.readStruct(0, gnm.DrawCommandBuffer.CmdAcquireMem);
            const addr_lo: u64 = aqm.coher_base_lo;
            const addr_hi: u64 = aqm.coher_base_hi.value;
            const len_lo = aqm.coher_size_lo;
            const len_hi: u64 = aqm.coher_size_hi.value;
            const byte_len = len_lo | (len_hi << 32);

            // HACK: not all AcquireMem packets have valid address.
            // so far this flag seems to always have a valid one.
            // TODO: are there any other flags with valid addresses?
            if (aqm.flags.coher_cntl.tc_wb_action_ena) {
                if (addr_lo != 0 or addr_hi != 0) {
                    const addr: [*]const u8 = @ptrFromInt((addr_lo << 8) | (addr_hi << 40));
                    const buf = addr[0..byte_len];
                    try self.dumpMemory(buf, @src());
                } else {
                    log.warn("Found an address in an acquire mem packet without an address!", .{});
                }
            }
        },
        .set_context_reg => {
            if (pkt.dwords.len >= 2) {
                const start_reg = gnm.ContextRegisterOffset + (try pkt.readDword(1) << 2);

                for (0..pkt.dwords.len - 2) |i| {
                    const reg_u32: u32 = @intCast(start_reg + (i << 2));
                    const reg: gnm.ContextRegister = @fromBackingInt(reg_u32);
                    const data = try pkt.readDword(2 + i);

                    switch (reg) {
                        else => {},
                        // render targets
                        .cb_color0_base => ctx.render_targets[0].base = data,
                        .cb_color0_pitch => ctx.render_targets[0].pitch = @bitCast(data),
                        .cb_color0_slice => ctx.render_targets[0].slice = @bitCast(data),
                        .cb_color0_view => ctx.render_targets[0].view = @bitCast(data),
                        .cb_color0_info => ctx.render_targets[0].info = @bitCast(data),
                        .cb_color0_attrib => ctx.render_targets[0].attrib = @bitCast(data),
                        .cb_color0_dcc_control => ctx.render_targets[0].dcc_control = @bitCast(data),
                        .cb_color0_cmask => ctx.render_targets[0].cmask = @bitCast(data),
                        .cb_color0_cmask_slice => ctx.render_targets[0].cmask_slice = @bitCast(data),
                        .cb_color0_fmask => ctx.render_targets[0].fmask = @bitCast(data),
                        .cb_color0_fmask_slice => ctx.render_targets[0].fmask_slice = @bitCast(data),
                        .cb_color0_clear_word0 => ctx.render_targets[0].clear_word0 = data,
                        .cb_color0_clear_word1 => ctx.render_targets[0].clear_word1 = data,
                        .cb_color0_dcc_base => ctx.render_targets[0].dcc_base = data,
                        .cb_color1_base => ctx.render_targets[1].base = data,
                        .cb_color1_pitch => ctx.render_targets[1].pitch = @bitCast(data),
                        .cb_color1_slice => ctx.render_targets[1].slice = @bitCast(data),
                        .cb_color1_view => ctx.render_targets[1].view = @bitCast(data),
                        .cb_color1_info => ctx.render_targets[1].info = @bitCast(data),
                        .cb_color1_attrib => ctx.render_targets[1].attrib = @bitCast(data),
                        .cb_color1_dcc_control => ctx.render_targets[1].dcc_control = @bitCast(data),
                        .cb_color1_cmask => ctx.render_targets[1].cmask = @bitCast(data),
                        .cb_color1_cmask_slice => ctx.render_targets[1].cmask_slice = @bitCast(data),
                        .cb_color1_fmask => ctx.render_targets[1].fmask = @bitCast(data),
                        .cb_color1_fmask_slice => ctx.render_targets[1].fmask_slice = @bitCast(data),
                        .cb_color1_clear_word0 => ctx.render_targets[1].clear_word0 = data,
                        .cb_color1_clear_word1 => ctx.render_targets[1].clear_word1 = data,
                        .cb_color1_dcc_base => ctx.render_targets[1].dcc_base = data,
                        .cb_color2_base => ctx.render_targets[2].base = data,
                        .cb_color2_pitch => ctx.render_targets[2].pitch = @bitCast(data),
                        .cb_color2_slice => ctx.render_targets[2].slice = @bitCast(data),
                        .cb_color2_view => ctx.render_targets[2].view = @bitCast(data),
                        .cb_color2_info => ctx.render_targets[2].info = @bitCast(data),
                        .cb_color2_attrib => ctx.render_targets[2].attrib = @bitCast(data),
                        .cb_color2_dcc_control => ctx.render_targets[2].dcc_control = @bitCast(data),
                        .cb_color2_cmask => ctx.render_targets[2].cmask = @bitCast(data),
                        .cb_color2_cmask_slice => ctx.render_targets[2].cmask_slice = @bitCast(data),
                        .cb_color2_fmask => ctx.render_targets[2].fmask = @bitCast(data),
                        .cb_color2_fmask_slice => ctx.render_targets[2].fmask_slice = @bitCast(data),
                        .cb_color2_clear_word0 => ctx.render_targets[2].clear_word0 = data,
                        .cb_color2_clear_word1 => ctx.render_targets[2].clear_word1 = data,
                        .cb_color2_dcc_base => ctx.render_targets[2].dcc_base = data,
                        .cb_color3_base => ctx.render_targets[3].base = data,
                        .cb_color3_pitch => ctx.render_targets[3].pitch = @bitCast(data),
                        .cb_color3_slice => ctx.render_targets[3].slice = @bitCast(data),
                        .cb_color3_view => ctx.render_targets[3].view = @bitCast(data),
                        .cb_color3_info => ctx.render_targets[3].info = @bitCast(data),
                        .cb_color3_attrib => ctx.render_targets[3].attrib = @bitCast(data),
                        .cb_color3_dcc_control => ctx.render_targets[3].dcc_control = @bitCast(data),
                        .cb_color3_cmask => ctx.render_targets[3].cmask = @bitCast(data),
                        .cb_color3_cmask_slice => ctx.render_targets[3].cmask_slice = @bitCast(data),
                        .cb_color3_fmask => ctx.render_targets[3].fmask = @bitCast(data),
                        .cb_color3_fmask_slice => ctx.render_targets[3].fmask_slice = @bitCast(data),
                        .cb_color3_clear_word0 => ctx.render_targets[3].clear_word0 = data,
                        .cb_color3_clear_word1 => ctx.render_targets[3].clear_word1 = data,
                        .cb_color3_dcc_base => ctx.render_targets[3].dcc_base = data,
                        .cb_color4_base => ctx.render_targets[4].base = data,
                        .cb_color4_pitch => ctx.render_targets[4].pitch = @bitCast(data),
                        .cb_color4_slice => ctx.render_targets[4].slice = @bitCast(data),
                        .cb_color4_view => ctx.render_targets[4].view = @bitCast(data),
                        .cb_color4_info => ctx.render_targets[4].info = @bitCast(data),
                        .cb_color4_attrib => ctx.render_targets[4].attrib = @bitCast(data),
                        .cb_color4_dcc_control => ctx.render_targets[4].dcc_control = @bitCast(data),
                        .cb_color4_cmask => ctx.render_targets[4].cmask = @bitCast(data),
                        .cb_color4_cmask_slice => ctx.render_targets[4].cmask_slice = @bitCast(data),
                        .cb_color4_fmask => ctx.render_targets[4].fmask = @bitCast(data),
                        .cb_color4_fmask_slice => ctx.render_targets[4].fmask_slice = @bitCast(data),
                        .cb_color4_clear_word0 => ctx.render_targets[4].clear_word0 = data,
                        .cb_color4_clear_word1 => ctx.render_targets[4].clear_word1 = data,
                        .cb_color4_dcc_base => ctx.render_targets[4].dcc_base = data,
                        .cb_color5_base => ctx.render_targets[5].base = data,
                        .cb_color5_pitch => ctx.render_targets[5].pitch = @bitCast(data),
                        .cb_color5_slice => ctx.render_targets[5].slice = @bitCast(data),
                        .cb_color5_view => ctx.render_targets[5].view = @bitCast(data),
                        .cb_color5_info => ctx.render_targets[5].info = @bitCast(data),
                        .cb_color5_attrib => ctx.render_targets[5].attrib = @bitCast(data),
                        .cb_color5_dcc_control => ctx.render_targets[5].dcc_control = @bitCast(data),
                        .cb_color5_cmask => ctx.render_targets[5].cmask = @bitCast(data),
                        .cb_color5_cmask_slice => ctx.render_targets[5].cmask_slice = @bitCast(data),
                        .cb_color5_fmask => ctx.render_targets[5].fmask = @bitCast(data),
                        .cb_color5_fmask_slice => ctx.render_targets[5].fmask_slice = @bitCast(data),
                        .cb_color5_clear_word0 => ctx.render_targets[5].clear_word0 = data,
                        .cb_color5_clear_word1 => ctx.render_targets[5].clear_word1 = data,
                        .cb_color5_dcc_base => ctx.render_targets[5].dcc_base = data,
                        .cb_color6_base => ctx.render_targets[6].base = data,
                        .cb_color6_pitch => ctx.render_targets[6].pitch = @bitCast(data),
                        .cb_color6_slice => ctx.render_targets[6].slice = @bitCast(data),
                        .cb_color6_view => ctx.render_targets[6].view = @bitCast(data),
                        .cb_color6_info => ctx.render_targets[6].info = @bitCast(data),
                        .cb_color6_attrib => ctx.render_targets[6].attrib = @bitCast(data),
                        .cb_color6_dcc_control => ctx.render_targets[6].dcc_control = @bitCast(data),
                        .cb_color6_cmask => ctx.render_targets[6].cmask = @bitCast(data),
                        .cb_color6_cmask_slice => ctx.render_targets[6].cmask_slice = @bitCast(data),
                        .cb_color6_fmask => ctx.render_targets[6].fmask = @bitCast(data),
                        .cb_color6_fmask_slice => ctx.render_targets[6].fmask_slice = @bitCast(data),
                        .cb_color6_clear_word0 => ctx.render_targets[6].clear_word0 = data,
                        .cb_color6_clear_word1 => ctx.render_targets[6].clear_word1 = data,
                        .cb_color6_dcc_base => ctx.render_targets[6].dcc_base = data,
                        .cb_color7_base => ctx.render_targets[7].base = data,
                        .cb_color7_pitch => ctx.render_targets[7].pitch = @bitCast(data),
                        .cb_color7_slice => ctx.render_targets[7].slice = @bitCast(data),
                        .cb_color7_view => ctx.render_targets[7].view = @bitCast(data),
                        .cb_color7_info => ctx.render_targets[7].info = @bitCast(data),
                        .cb_color7_attrib => ctx.render_targets[7].attrib = @bitCast(data),
                        .cb_color7_dcc_control => ctx.render_targets[7].dcc_control = @bitCast(data),
                        .cb_color7_cmask => ctx.render_targets[7].cmask = @bitCast(data),
                        .cb_color7_cmask_slice => ctx.render_targets[7].cmask_slice = @bitCast(data),
                        .cb_color7_fmask => ctx.render_targets[7].fmask = @bitCast(data),
                        .cb_color7_fmask_slice => ctx.render_targets[7].fmask_slice = @bitCast(data),
                        .cb_color7_clear_word0 => ctx.render_targets[7].clear_word0 = data,
                        .cb_color7_clear_word1 => ctx.render_targets[7].clear_word1 = data,
                        .cb_color7_dcc_base => ctx.render_targets[7].dcc_base = data,
                        // depth render targets
                        .db_z_info => ctx.depth_render_target.z_info = @bitCast(data),
                        .db_stencil_info => ctx.depth_render_target.stencil_info = @bitCast(data),
                        .db_z_read_base => ctx.depth_render_target.z_read_base = data,
                        .db_stencil_read_base => ctx.depth_render_target.stencil_read_base = data,
                        .db_z_write_base => ctx.depth_render_target.z_write_base = data,
                        .db_stencil_write_base => ctx.depth_render_target.stencil_write_base = data,
                        .db_depth_size => ctx.depth_render_target.depth_size = @bitCast(data),
                        .db_depth_slice => ctx.depth_render_target.depth_slice = @bitCast(data),
                        .db_depth_view => ctx.depth_render_target.depth_view = @bitCast(data),
                        .db_htile_data_base => ctx.depth_render_target.htile_data_base = data,
                        .db_htile_surface => ctx.depth_render_target.htile_surface = @bitCast(data),
                        .db_depth_info => ctx.depth_render_target.depth_info = @bitCast(data),
                    }
                }
            }
        },
        .set_sh_reg => {
            if (pkt.dwords.len >= 2) {
                const start_reg = gnm.ShRegisterOffset + (try pkt.readDword(1) << 2);

                for (0..pkt.dwords.len - 2) |i| {
                    const reg_u32: u32 = @intCast(start_reg + (i << 2));
                    const reg: gnm.ShRegister = @fromBackingInt(reg_u32);
                    const data = try pkt.readDword(i + 2);

                    switch (reg) {
                        else => {},
                        // shader byte code address
                        .spi_shader_pgm_lo_ps => ctx.shaders.ps.address.low = data,
                        .spi_shader_pgm_hi_ps => ctx.shaders.ps.address.high = data,
                        .spi_shader_pgm_lo_vs => ctx.shaders.vs.address.low = data,
                        .spi_shader_pgm_hi_vs => ctx.shaders.vs.address.high = data,
                        // shader user data
                        .spi_shader_user_data_ps_0 => ctx.user_data.ps[0] = data,
                        .spi_shader_user_data_ps_1 => ctx.user_data.ps[1] = data,
                        .spi_shader_user_data_ps_2 => ctx.user_data.ps[2] = data,
                        .spi_shader_user_data_ps_3 => ctx.user_data.ps[3] = data,
                        .spi_shader_user_data_ps_4 => ctx.user_data.ps[4] = data,
                        .spi_shader_user_data_ps_5 => ctx.user_data.ps[5] = data,
                        .spi_shader_user_data_ps_6 => ctx.user_data.ps[6] = data,
                        .spi_shader_user_data_ps_7 => ctx.user_data.ps[7] = data,
                        .spi_shader_user_data_ps_8 => ctx.user_data.ps[8] = data,
                        .spi_shader_user_data_ps_9 => ctx.user_data.ps[9] = data,
                        .spi_shader_user_data_ps_10 => ctx.user_data.ps[10] = data,
                        .spi_shader_user_data_ps_11 => ctx.user_data.ps[11] = data,
                        .spi_shader_user_data_ps_12 => ctx.user_data.ps[12] = data,
                        .spi_shader_user_data_ps_13 => ctx.user_data.ps[13] = data,
                        .spi_shader_user_data_ps_14 => ctx.user_data.ps[14] = data,
                        .spi_shader_user_data_ps_15 => ctx.user_data.ps[15] = data,
                        .spi_shader_user_data_vs_0 => ctx.user_data.vs[0] = data,
                        .spi_shader_user_data_vs_1 => ctx.user_data.vs[1] = data,
                        .spi_shader_user_data_vs_2 => ctx.user_data.vs[2] = data,
                        .spi_shader_user_data_vs_3 => ctx.user_data.vs[3] = data,
                        .spi_shader_user_data_vs_4 => ctx.user_data.vs[4] = data,
                        .spi_shader_user_data_vs_5 => ctx.user_data.vs[5] = data,
                        .spi_shader_user_data_vs_6 => ctx.user_data.vs[6] = data,
                        .spi_shader_user_data_vs_7 => ctx.user_data.vs[7] = data,
                        .spi_shader_user_data_vs_8 => ctx.user_data.vs[8] = data,
                        .spi_shader_user_data_vs_9 => ctx.user_data.vs[9] = data,
                        .spi_shader_user_data_vs_10 => ctx.user_data.vs[10] = data,
                        .spi_shader_user_data_vs_11 => ctx.user_data.vs[11] = data,
                        .spi_shader_user_data_vs_12 => ctx.user_data.vs[12] = data,
                        .spi_shader_user_data_vs_13 => ctx.user_data.vs[13] = data,
                        .spi_shader_user_data_vs_14 => ctx.user_data.vs[14] = data,
                        .spi_shader_user_data_vs_15 => ctx.user_data.vs[15] = data,
                        .compute_user_data_0 => ctx.user_data.cs[0] = data,
                        .compute_user_data_1 => ctx.user_data.cs[1] = data,
                        .compute_user_data_2 => ctx.user_data.cs[2] = data,
                        .compute_user_data_3 => ctx.user_data.cs[3] = data,
                        .compute_user_data_4 => ctx.user_data.cs[4] = data,
                        .compute_user_data_5 => ctx.user_data.cs[5] = data,
                        .compute_user_data_6 => ctx.user_data.cs[6] = data,
                        .compute_user_data_7 => ctx.user_data.cs[7] = data,
                        .compute_user_data_8 => ctx.user_data.cs[8] = data,
                        .compute_user_data_9 => ctx.user_data.cs[9] = data,
                        .compute_user_data_10 => ctx.user_data.cs[10] = data,
                        .compute_user_data_11 => ctx.user_data.cs[11] = data,
                        .compute_user_data_12 => ctx.user_data.cs[12] = data,
                        .compute_user_data_13 => ctx.user_data.cs[13] = data,
                        .compute_user_data_14 => ctx.user_data.cs[14] = data,
                        .compute_user_data_15 => ctx.user_data.cs[15] = data,
                    }
                }
            }
        },
    }
}

inline fn toIndexByteLen(idx_size: gnm.IndexSize) u3 {
    return switch (idx_size) {
        .@"8" => @sizeOf(u8),
        .@"16" => @sizeOf(u16),
        .@"32" => @sizeOf(u32),
    };
}

fn onGraphicsDraw(self: *Frametracer, ctx: *ParserContext) !void {
    if (ctx.shaders.cs.toAddress() != 0) try self.traceShaderResources(ctx, ctx.shaders.cs, .cs);
    if (ctx.shaders.ps.toAddress() != 0) try self.traceShaderResources(ctx, ctx.shaders.ps, .ps);
    if (ctx.shaders.vs.toAddress() != 0) try self.traceShaderResources(ctx, ctx.shaders.vs, .vs);
    if (ctx.shaders.gs.toAddress() != 0) try self.traceShaderResources(ctx, ctx.shaders.gs, .gs);
    if (ctx.shaders.es.toAddress() != 0) try self.traceShaderResources(ctx, ctx.shaders.es, .es);
    if (ctx.shaders.hs.toAddress() != 0) try self.traceShaderResources(ctx, ctx.shaders.hs, .hs);
    if (ctx.shaders.ls.toAddress() != 0) try self.traceShaderResources(ctx, ctx.shaders.ls, .ls);

    for (ctx.render_targets) |rt| {
        if (rt.base != 0 and rt.info.format != .invalid) {
            const addr = rt.getBaseAddressAs(u8);
            const size_info = try rt.calcByteSize();
            const data = addr[0..size_info.length];
            try self.dumpMemory(data, @src());
        }
    }

    const drt = ctx.depth_render_target;
    if (drt.z_info.format != .invalid) {
        const maybe_zread = drt.getZReadAddressAs(u8);
        if (maybe_zread) |zread| {
            const size_info = try drt.calcByteSize();
            const data = zread[0..size_info.length];
            try self.dumpMemory(data, @src());
        }
        const maybe_zwrite = drt.getZWriteAddressAs(u8);
        if (maybe_zwrite) |zwrite| {
            const size_info = try drt.calcByteSize();
            const data = zwrite[0..size_info.length];
            try self.dumpMemory(data, @src());
        }
    } // TODO: trace stencil sread and swrite
}

fn traceShaderResources(
    self: *Frametracer,
    ctx: *ParserContext,
    sh: ParserContext.Shader,
    stage: gnm.ShaderStage,
) !void {
    if (sh.address.low == 0xfe000f1 and sh.address.high == 0) {
        @branchHint(.cold);
        log.debug("Ignoring embedded vertex shader", .{});
        return;
    }

    const code = sh.getByteCode() catch |err| {
        log.warn("Failed to get shader 0x{x}'s length with {t}, trying fallback", .{
            sh.toAddress(),
            err,
        });

        // try dumping at least the page where the code start address is
        const code_addr = sh.toAddress();
        if (Kernel.virtualQueryInfo(@ptrFromInt(code_addr))) |region_info| {
            const remain_len = region_info.virtual_end - code_addr;
            const some_code = @as([*]const u8, @ptrFromInt(code_addr))[0..remain_len];
            try self.dumpMemory(some_code, @src());
        } else |virt_err| {
            log.err("Fallback VirtualQueryInfo for shader at 0x{x} failed with {t}", .{
                sh.toAddress(),
                virt_err,
            });
        }
        return error.UnknownShaderLimits;
    };

    try self.dumpMemory(@ptrCast(code), @src());

    const user_data = switch (stage) {
        .cs => &ctx.user_data.cs,
        .ps => &ctx.user_data.ps,
        .vs => &ctx.user_data.vs,
        .gs => &ctx.user_data.gs,
        .es => &ctx.user_data.es,
        .hs => &ctx.user_data.hs,
        .ls => &ctx.user_data.ls,
    };

    defer _ = self.analyzer_arena.reset(.retain_capacity);
    const scan = try buildResourceList(self.analyzer_arena.allocator(), code, user_data);

    for (scan.resources) |rsrc| {
        const resource_ptr = try scan.accessResource(rsrc, user_data);

        // const region_info = Kernel.virtualQueryInfo(@ptrCast(resource_ptr)) catch |err| {
        //     log.err("Address {*} for resource {t} in shader {*} is invalid. Query error: {t}", .{
        //         resource_ptr,
        //         rsrc.info,
        //         code.ptr,
        //         err,
        //     });
        //     continue;
        // };
        // std.debug.print("Ud {t}'s resource {*} in shader {*} region {x}-{x}\n", .{
        //     rsrc.info,
        //     resource_ptr,
        //     code.ptr,
        //     region_info.virtual_start,
        //     region_info.virtual_end,
        // });

        switch (rsrc.info) {
            .sampler => {},
            .image => {
                const desc: *const gnm.Texture = @ptrCast(@alignCast(resource_ptr));
                const addr = desc.getBaseAddressAs(u8);
                const size_info = try desc.calcByteSize();
                const data = addr[0..size_info.length];
                try self.dumpMemory(data, @src());
            },
            .storage_buffer, .uniform_buffer => {
                const desc: *const gnm.Buffer = @ptrCast(@alignCast(resource_ptr));
                const addr = desc.getBaseAddressAs(u8);
                const byte_len: usize = desc.reg2.num_records * desc.reg1.stride;
                const data = addr[0..byte_len];
                try self.dumpMemory(data, @src());
            },
            .code => {
                const code_ptr: [*]const u32 = @ptrCast(@alignCast(resource_ptr));
                const dword_len = calcFetchDwords(code_ptr);
                const data = code_ptr[0..dword_len];
                try self.dumpMemory(@ptrCast(data), @src());
            },
        }
    }
}

fn buildResourceList(
    arena_alloc: mem.Allocator,
    shader_code: []const u32,
    ud: []const u32,
) !gcn.Analyzer {
    // find base shader's resources
    var base_analysis = try gcn.Analyzer.scan(arena_alloc, shader_code, .{});

    // find all function pointers in base shader,
    // and make a list of all code-only resources
    var maybe_next_access_idx: ?gcn.Analyzer.Access.Id = null;
    var maybe_code_accesses: ?[]gcn.Analyzer.Access = null;

    for (base_analysis.resources) |rsrc| {
        if (rsrc.info != .code)
            continue;

        const code_ptr = try base_analysis.accessResource(rsrc, ud);
        const num_dwords = calcFetchDwords(code_ptr);
        const code = code_ptr[0..num_dwords];

        // append its resources to the base shader
        var func_analysis = try gcn.Analyzer.scan(arena_alloc, code, .{
            .external_accesses = maybe_code_accesses,
            .export_accesses = true,
        });

        if (maybe_code_accesses) |accesses| {
            arena_alloc.free(accesses);
        }
        maybe_code_accesses = func_analysis.accesses.?;
        maybe_next_access_idx = func_analysis.next_access_index.?;
        func_analysis.accesses = null;
    }

    // perform the full analysis with code-only resources AND the base shader
    const full_analysis = try gcn.Analyzer.scan(arena_alloc, shader_code, .{
        .external_accesses = maybe_code_accesses,
        .next_access_index = maybe_next_access_idx,
    });
    return full_analysis;
}

// TODO: get memory region size and fail if it overflows
fn calcFetchDwords(code: [*]const u32) u32 {
    // find the start of the s_setpc_b64 instruction
    var count: u32 = 0;
    while (code[count] != 0xbe802000) {
        count += 1;
    }
    // add the s_setpc_b64 instruction size
    count += 1;
    return count;
}

const ParserContext = struct {
    const empty = ParserContext{
        .index_count = 0,
        .index_elem_size = .@"16",
        .index_buffer = null,

        .indirect_buffer = null,

        .shaders = .{
            .cs = .empty,
            .ps = .empty,
            .vs = .empty,
            .gs = .empty,
            .es = .empty,
            .hs = .empty,
            .ls = .empty,
        },
        .user_data = .{
            .cs = @splat(0),
            .ps = @splat(0),
            .vs = @splat(0),
            .gs = @splat(0),
            .es = @splat(0),
            .hs = @splat(0),
            .ls = @splat(0),
        },

        .render_targets = @splat(.init),
        .depth_render_target = .init,
    };

    const Shader = struct {
        const empty = Shader{ .address = .{ .low = 0, .high = 0 } };

        address: packed struct(u64) {
            low: u32,
            high: u32,
        },

        fn toAddress(self: Shader) u64 {
            return @as(u64, @bitCast(self.address)) << 8;
        }

        fn getByteCode(self: ParserContext.Shader) ![]const u32 {
            const length = try self.calcShaderSize();
            const code: [*]const u8 = @ptrFromInt(self.toAddress());
            return @ptrCast(@alignCast(code[0..length]));
        }

        fn calcShaderSize(self: ParserContext.Shader) !usize {
            const address: u64 = @bitCast(self.toAddress());
            if (address == 0)
                return error.CodeAddressNull;

            const code: [*]const u32 = @ptrFromInt(address);

            // TODO: get max possible reasonable! memory region
            var it = gcn.Decoder.init(code[0..0x10000]);
            while (try it.nextInstruction()) |instr| {
                // if this is tool generated code then it might have shader binary info.
                // check if the first instruction is a "s_mov_b32 vcc_hi, [literal]"
                // and get its literal to use in length calculation.
                if (instr.offset == 0) {
                    if (instr.microcode == .sop1 and
                        instr.data.sop1.opcode == .s_mov_b32 and
                        instr.dsts[0].field == .vcc_hi and
                        instr.srcs[0].field == .literal_const)
                    {
                        const num_words = instr.srcs[0].toConstantU32().?;
                        const sbi_offset = ((num_words + 1) * 2) * @sizeOf(u32);
                        const sbi: *const gnm.ShaderBinaryInfo =
                            @ptrFromInt(address + sbi_offset);

                        // other emulators may require ShaderBinaryInfo's data,
                        // so dump it if it's available along with GCN bytecode
                        return sbi_offset +
                            @sizeOf(gnm.ShaderBinaryInfo) +
                            (sbi.num_input_usage_slots * @sizeOf(gnm.InputUsageSlot));
                    }
                }

                // fallback to finding s_endpgm
                if (instr.microcode == .sopp and instr.data.sopp.opcode == .s_endpgm)
                    return instr.offset + instr.length;
            }

            return error.NoEnding;
        }
    };

    index_count: u32,
    index_elem_size: gnm.IndexSize,
    index_buffer: ?[*]const u8,

    indirect_buffer: ?[*]const u8,

    shaders: struct {
        cs: Shader,
        ps: Shader,
        vs: Shader,
        gs: Shader,
        es: Shader,
        hs: Shader,
        ls: Shader,
    },
    user_data: struct {
        cs: [16]u32,
        ps: [16]u32,
        vs: [16]u32,
        gs: [16]u32,
        es: [16]u32,
        hs: [16]u32,
        ls: [16]u32,
    },

    render_targets: [8]gnm.RenderTarget,
    depth_render_target: gnm.DepthRenderTarget,
};

const Jailbreak = struct {
    old_prison: mira.PrisonInfo,

    fn obtain() !Jailbreak {
        const old_prison = try mira.escapePrison();
        return .{ .old_prison = old_prison };
    }
    fn restore(self: Jailbreak) !void {
        try mira.returnPrison(self.old_prison);
    }
};
