let cmod = new CModule(File.readAllText(args.work_dir + "/stalk_event_handler.c"));

let mainModule = Process.enumerateModules().find(m => m.name.endsWith(".exe"));
let memRanges = Process.enumerateRanges({ coalesce: true, protection: "rw-" });
memRanges.sort((a, b) => a.base.compare(b.base)); //must be sorted as cmod will binary search entries.

let callbacks = {
    flush_events: new NativeCallback(flushEvents, "void", ["pointer", "int32"]),
    console_log: new NativeCallback(msg => console.log(msg.readUtf8String()), "void", ["pointer"])
};
const ps = Process.pointerSize;

let agentCtx = Memory.alloc(128);
let memRangesPtr = Memory.alloc(memRanges.length * ps * 2);
let threadCtxs = [];

let pos = 0;

for (let range of memRanges) {
    memRangesPtr.add(pos).writePointer(range.base); pos += ps;
    memRangesPtr.add(pos).writePointer(range.base.add(range.size)); pos += ps;
}

pos = 0;
agentCtx.add(pos).writePointer(mainModule.base); pos += ps;
agentCtx.add(pos).writePointer(mainModule.base.add(mainModule.size)); pos += ps;
agentCtx.add(pos).writePointer(memRangesPtr); pos += ps;
agentCtx.add(pos).writeU32(memRanges.length); pos += 8; //num_valid_mem_ranges, align padding
agentCtx.add(pos).writePointer(callbacks.flush_events); pos += ps;
agentCtx.add(pos).writePointer(callbacks.console_log); pos += ps;

for (let thread of findCallingThreads(mainModule)) {
    let ctx = Memory.alloc(1024 * 64);
    pos = 0;
    ctx.add(pos).writePointer(agentCtx); pos += ps;
    ctx.add(pos).writeU64(0); pos += 8; //gum_event_id, event_buffer_pos

    Stalker.follow(thread.id, {
        events: { call: true },
        onEvent: cmod.process_event,
        //TODO: maybe use a custom transformer to filter only indirect calls
        data: ctx
    });
    threadCtxs.push(ctx); //add ref to prevent mem from being GC'ed
}

//Find threads containing a stackframe for a function inside the given module
function findCallingThreads(module) {
    let threads = [];

    for (let thread of Process.enumerateThreads()) {
        let stacktrace = Thread.backtrace(thread.context, Backtracer.FUZZY);
        let funcAddr = stacktrace.find(s => s.compare(module.base) >= 0 && s.compare(module.base.add(module.size)) < 0);

        if (funcAddr) {
            console.log(`${thread.id} ${module.name}+${funcAddr.sub(module.base)}`);
            threads.push(thread);
        }
    }
    return threads;
}

function flushEvents(ptr, count) {
    let path = args.output_dir + "/tid_" + Process.getCurrentThreadId() + ".dat";
    let file = new File(path, "a+b");
    file.write(ptr.readByteArray(count * 12));
    file.close();
}