#include <gum/gumstalker.h>

// Record one call event every other N. Must be a pow2 minus one.
#define EVENT_SKIP_FREQ     0
#define EVENT_BUFFER_SIZE   ((1024 * 64 - 32) / sizeof(EventRecord))

// Note: values are relative to `agent_ctx->module_start`
typedef struct {
    uint32_t origin;
    uint32_t target;
    uint32_t vtable;
} EventRecord;

typedef struct {
    uintptr_t start;
    uintptr_t end;
} MemRange;

typedef struct {
    uintptr_t module_start, module_end;

    MemRange* valid_mem_ranges;
    uint32_t num_valid_mem_ranges;
    uint32_t _align_pad1;

    void (*flush_events)(const EventRecord* events, int32_t count);
    void (*console_log)(const char* msg);
} AgentContext;

typedef struct {
    AgentContext* agent_ctx;
    uint32_t gum_event_id;
    uint32_t event_buffer_pos;
    EventRecord event_buffer[EVENT_BUFFER_SIZE];
} EventHandlerContext;

void debugln(AgentContext* ctx, const char* format, ...) {
    va_list args;
    va_start(args, format);
    char* message = g_strdup_vprintf(format, args);
    va_end(args);

    ctx->console_log(message);
    g_free(message);
}

bool is_valid_ptr(AgentContext* ctx, uintptr_t ptr) {
    if (ptr & (GLIB_SIZEOF_VOID_P - 1)) return false; //unaligned

    int32_t lo = 0, hi = ctx->num_valid_mem_ranges - 1;

    while (lo <= hi) {
        int32_t mid = (lo + hi) / 2;
        MemRange* rng = &ctx->valid_mem_ranges[mid];

        if (ptr < rng->start) {
            hi = mid - 1;
        } else if (ptr >= rng->end) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

bool is_inside_module(AgentContext* ctx, uintptr_t ptr) {
    return ptr >= ctx->module_start && ptr <= ctx->module_end;
}

void process_event(const GumEvent* event, GumCpuContext* cpu, EventHandlerContext* ctx) {
    if ((ctx->gum_event_id++ & EVENT_SKIP_FREQ) != 0) return;

#if GLIB_SIZEOF_VOID_P == 8
    uintptr_t rcx = cpu->rcx, rip = cpu->rip;
#else
    uintptr_t rcx = cpu->ecx, rip = cpu->eip;
#endif

    if (!is_inside_module(ctx->agent_ctx, (uintptr_t)event->call.target) || !is_valid_ptr(ctx->agent_ctx, rcx)) return;

    uintptr_t vtable = *(uintptr_t*)rcx;
    if (!is_inside_module(ctx->agent_ctx, vtable)) return;

    if (ctx->event_buffer_pos >= EVENT_BUFFER_SIZE) {
        ctx->agent_ctx->flush_events(ctx->event_buffer, ctx->event_buffer_pos);
        ctx->event_buffer_pos = 0;
    }
    EventRecord* rc = &ctx->event_buffer[ctx->event_buffer_pos++];
    uintptr_t ptr_base = ctx->agent_ctx->module_start;
    rc->origin = (uint32_t)(uintptr_t)(event->call.location - ptr_base);
    rc->target = (uint32_t)(uintptr_t)(event->call.target - ptr_base);
    rc->vtable = (uint32_t)(uintptr_t)(vtable - ptr_base);

    //debugln(ctx->agent_ctx, "#%d origin=%p target=%p vtbl=%p", ctx->gum_event_id, rc->origin, rc->target, rc->vtable);
}
