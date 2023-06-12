//Recovers object type hierarcy using information collected during program runtime.
//@category C++

import java.io.*;
import java.util.*;

import ghidra.app.plugin.core.decompile.actions.*;
import ghidra.app.script.*;
import ghidra.program.database.data.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.*;

public class FridaTraceImporter extends GhidraScript {
    static final int MAX_VTABLE_SIZE = 1024;

    HashMap<Integer, FuncInfo> functions = new HashMap<>();
    HashSet<Integer> vtables = new HashSet<>();

    @Override
    public void run() throws Exception {
        try {
            File dir = askDirectory("Directory containing collected data", "Choose directory");

            for (File file : dir.listFiles()) {
                printf("Loading trace '%s'...\n", file.getName());
                loadTrace(file);
            }
            printf("Found %d virtual functions, %d unique vtables...\n", functions.size(), vtables.size());

            Address baseAddr = currentProgram.getImageBase();
            int ptrSize = currentProgram.getDefaultPointerSize();
            FunctionManager funcMgr = currentProgram.getFunctionManager();

            HashMap<FuncRelationKey, ResolvedClass> resolvedClasses = new HashMap<>();

            // Scan VTables for contained functions and create class types
            for (int relAddr : vtables) {
                Address addr = baseAddr.add(relAddr);
                MemoryBlock mem = currentProgram.getMemory().getBlock(addr);

                if (mem == null || (mem.getPermissions() & MemoryBlock.WRITE) != 0) {
                    printerr("Warn: skipping vtable inside writeable memory block " + addr);
                    continue;
                }
                byte[] tableData = new byte[MAX_VTABLE_SIZE * ptrSize];
                int tableSize = mem.getBytes(addr, tableData);

                for (int pos = 0; pos < tableSize; pos += ptrSize) {
                    long funcAddr = readIntLE(tableData, pos);
                    if (ptrSize == 8) {
                        funcAddr |= (long) readIntLE(tableData, pos + 4) << 32;
                    }

                    Function func = funcMgr.getFunctionContaining(baseAddr.getNewAddress(funcAddr));

                    if (func == null)
                        break;

                    func.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);

                    Parameter thisPar = func.getParameter(0);

                    if (thisPar == null || (thisPar.getAutoParameterType() == AutoParameterType.THIS &&
                            CreateStructureVariableAction.getStructureForExtending(thisPar.getDataType()) != null)) {
                        printf("Warn: skipping unresolved or modified function %s\n", func.getName());
                        continue;
                    }

                    FuncRelationKey key = getFuncRelationKey(relAddr, (int) (funcAddr - baseAddr.getOffset()));
                    ResolvedClass klass = resolvedClasses.get(key);
                    if (klass == null) {
                        klass = new ResolvedClass(currentProgram, "VirtClass" + (resolvedClasses.size() + 1));
                        resolvedClasses.put(key, klass);
                    }
                    //func.setParentNamespace(klass.namespace);
                    func.setCustomVariableStorage(true);
                    func.getParameter(0).setDataType(new PointerDataType(klass.classType), SourceType.IMPORTED);
                    func.removeParameter(func.getParameterCount() - 1);
                }
            }

            printf("Created %d new classes\n", resolvedClasses.size());

            // Link cross refs
            HashSet<Address> virtCalls = new HashSet<>();
            for (Map.Entry<Integer, FuncInfo> entry : functions.entrySet()) {
                Address addr = baseAddr.add(entry.getKey());
                FuncInfo func = entry.getValue();

                for (int callRelAddr : func.callAddrs) {
                    Address callAddr = baseAddr.add(callRelAddr);

                    currentProgram.getReferenceManager().addMemoryReference(
                            callAddr, addr, RefType.COMPUTED_CALL, SourceType.IMPORTED, 0);

                    virtCalls.add(callAddr);
                }
            }
            printf("Linked cross references for %d calls\n", virtCalls.size());

            // This is commented out because Ghidra doesn't seem to provide a way to get data flow from registers.
            // The pcode trees can be pattern matched and all but at the end we get a register node with no other info at all,
            // e.g. in "obj->other->method(...)"  if "obj" is a parameter, we'll just see "RCX" which could've been reassigned.
           /*
            // Fix-up object field accesses based on virtual calls
            DecompInterface decomp = new DecompInterface();
            decomp.toggleCCode(false);
            decomp.setSimplificationStyle("normalize");
            decomp.openProgram(currentProgram);

            for (Address callAddr : virtCalls) {
                Function func = funcMgr.getFunctionContaining(callAddr);
                if (!func.getName().equals("FUN_140003f34"))
                    continue;

                printf("Call %s at %s\n", func, callAddr);
                DecompileResults decompRes = decomp.decompileFunction(func, 0, new ConsoleTaskMonitor());
                if (!decompRes.decompileCompleted())
                    continue;

                HighFunction highFunc = decompRes.getHighFunction();

                PcodeOp callNode = Iterators.tryFind(highFunc.getPcodeOps(callAddr), n -> n.getOpcode() == PcodeOp.CALLIND).orNull();
                if (callNode != null) {
                    propagateTypeFromVirtCall(highFunc, callNode);
                }
            }
            decomp.closeProgram();*/
        } catch (IllegalArgumentException ex) {
            Msg.warn(this, "Error during processing: " + ex.toString());
        }
    }

    private void propagateTypeFromVirtCall(HighFunction func, PcodeOp callNode) throws Exception {
        //MOV        this, qword ptr [RCX  + this+0x10]
        //MOV        RBX, param_2
        //MOV        RAX, qword ptr [this->vtbl]
        //CALL       qword ptr [RAX + 0x8]=>FUN_140003e48

        //targetObj = LOAD(INT_ADD(RCX, 16))
        //vtblBase  = LOAD(targetObj)
        //vtblAddr  = INT_ADD(vtblBase, 8)
        //funcAddr  = LOAD(vtblAddr)
        //CALLIND(funcAddr)

        PcodeOp funcAddr = callNode.getInput(0).getDef();
        if (funcAddr == null || funcAddr.getOpcode() != PcodeOp.LOAD) return;
        
        PcodeOp vtblAddr = funcAddr.getInput(1).getDef();
        if (vtblAddr.getOpcode() != PcodeOp.INT_ADD) return;
        
        PcodeOp vtblBase = vtblAddr.getInput(0).getDef();
        Varnode vtblOffs = vtblAddr.getInput(1);

        if (vtblBase == null || vtblBase.getOpcode() != PcodeOp.LOAD || !vtblOffs.isConstant()) return;

        PcodeOp targetObj = vtblBase.getInput(1).getDef();
        if (targetObj == null || targetObj.getOpcode() != PcodeOp.LOAD) return;
        
        targetObj = targetObj.getInput(1).getDef();
        if (targetObj == null || targetObj.getOpcode() != PcodeOp.INT_ADD) return;

        Varnode sourceObj = targetObj.getInput(0);
        Varnode sourceField = targetObj.getInput(1);

        printf(" FuncAddr   =%s\n", funcAddr);
        printf(" TableEntry = %s + %s\n", vtblBase, vtblOffs.getOffset());
        printf(" TargetObj  = %s\n", sourceObj, sourceField.getOffset(), targetObj);
        if (!sourceObj.isRegister() || !sourceField.isConstant()) return;

        Address instAddr = targetObj.getSeqnum().getTarget();
        //int scopeStart = (int)instAddr.subtract(func.getFunction().getEntryPoint());
        //Register reg = currentProgram.getRegister(sourceObj);
        //Variable var = new LocalVariableImpl("virtobj" + scopeStart, scopeStart, new PointerDataType(IntegerDataType.dataType), reg, currentProgram);
        //func.getFunction().addLocalVariable(var, SourceType.IMPORTED);
    }

    private FuncRelationKey getFuncRelationKey(int vtableAddr, int funcAddr) {
        FuncInfo info = functions.get(funcAddr);
        int[] keys;

        if (info != null) {
            keys = info.relatedVTables.stream().mapToInt(Number::intValue).toArray();
        } else {
            keys = new int[] { vtableAddr };
        }
        return new FuncRelationKey(keys);
    }

    private void loadTrace(File file) throws IOException {
        try (FileInputStream fs = new FileInputStream(file)) {
            final int RECORD_SIZE = 12;
            byte[] buffer = new byte[RECORD_SIZE * 1024];
            int bytesRead;

            // Read multiple entries at a time because read calls are ridiculously slow
            while ((bytesRead = fs.readNBytes(buffer, 0, buffer.length)) > 0) {
                for (int i = 0; i < bytesRead / RECORD_SIZE; i++) {
                    int originAddr = readIntLE(buffer, i * RECORD_SIZE + 0);
                    int targetAddr = readIntLE(buffer, i * RECORD_SIZE + 4);
                    int vtableAddr = readIntLE(buffer, i * RECORD_SIZE + 8);

                    FuncInfo funcInfo = functions.get(targetAddr);
                    if (funcInfo == null) {
                        funcInfo = new FuncInfo();
                        functions.put(targetAddr, funcInfo);
                    }
                    funcInfo.callAddrs.add(originAddr);
                    funcInfo.relatedVTables.add(vtableAddr);
                    vtables.add(vtableAddr);
                }
            }
        }
    }

    private static int readIntLE(byte[] buffer, int pos) {
        return (buffer[pos + 0] & 0xFF) << 0 |
               (buffer[pos + 1] & 0xFF) << 8 |
               (buffer[pos + 2] & 0xFF) << 16 |
               (buffer[pos + 3] & 0xFF) << 24;
    }
    
    static class FuncInfo {
        public final HashSet<Integer> callAddrs = new HashSet<>();
        public final HashSet<Integer> relatedVTables = new HashSet<>();
        public Function def;
    }

    static class ResolvedClass {
        public final GhidraClass namespace;
        public final StructureDataType tableType;
        public final StructureDataType classType;

        public ResolvedClass(Program prog, String name) throws Exception {
            namespace = prog.getSymbolTable().createClass(prog.getGlobalNamespace(), name, SourceType.IMPORTED);

            CategoryPath cat = DataTypeUtilities.getDataTypeCategoryPath(
                    prog.getPreferredRootNamespaceCategoryPath(), namespace.getParentNamespace());
            
            if (cat == null) {
                cat = CategoryPath.ROOT;
            }
            cat = cat.extend("TracedClasses");

            DataTypeManager dtm = prog.getDataTypeManager();
            Pointer voidPtr = dtm.getPointer(VoidDataType.dataType);

            tableType = new StructureDataType(cat, namespace.getName() + "__vtable", 0, dtm);
            for (int i = 0; i < 4; i++) {
                //new FunctionDefinitionDataType(null, dtm)
                tableType.add(voidPtr, voidPtr.getLength(), "func_" + i, null);
            }

            classType = new StructureDataType(cat, namespace.getName(), 0, dtm);
            Pointer tablePtr = dtm.getPointer(tableType);
            classType.add(tablePtr, tablePtr.getLength(), "vtbl", null);
            classType.add(new ArrayDataType(ByteDataType.dataType, 4096, 1));

            dtm.addDataType(tableType, DataTypeConflictHandler.DEFAULT_HANDLER);
            dtm.addDataType(classType, DataTypeConflictHandler.DEFAULT_HANDLER);
        }
    }
    
    static class FuncRelationKey {
        final int[] addrs;

        public FuncRelationKey(int[] addrs) {
            this.addrs = addrs;
            Arrays.sort(addrs);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(addrs);
        }
        @Override
        public boolean equals(Object obj) {
            return obj instanceof FuncRelationKey other && Arrays.equals(addrs, other.addrs);
        }
    }
}
