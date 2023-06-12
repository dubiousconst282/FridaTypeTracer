# FridaTypeTracer
Ghidra plugin for recovering virtual object type information using data traced at runtime via Frida

---

Call instrumentation is done using a [Frida stalker](https://frida.re/docs/stalker/) injected in the target process. It probes the `rcx/ecx` register to check for possible object instances - those who point to a valid memory region within the process and also references a static address in the process module.

The data is collected into a file for later use by the Ghidra plugin to generate types (using a very crude approach), assign function parameter types, and link cross references.

Further information could be captured in order to trace type information for parameters other than `this`, however that is likely to be considerably more complicated to implement.

## Usage
1. Install Frida and clone repo: `pip install frida-tools ; git clone https://github.com/dubiousconst282/FridaTypeTracer`
2. Instrument process: `python FridaTypeTracer/capture.py target_app.exe trace_data/`
3. Load and run `FridaTraceImporter.java` via _Ghidra Script Manager_

The definition `EVENT_SKIP_FREQ` in `stalk_event_handler.c` may be changed to a higher value to improve performance and reduce the amount of data generated.