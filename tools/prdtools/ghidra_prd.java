/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Given a routine, show all the calls to that routine and their parameters.
//    Place the cursor on a function (can be an external .dll function).
//    Execute the script.
//    The decompiler will be run on everything that calls the function at the cursor
//    All calls to the function will display with their parameters to the function.
//
//   This script assumes good flow, that switch stmts are good.
//
//@category Functions

import java.util.Iterator;
import java.util.stream.Collectors;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.util.exception.CancelledException;


import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

import java.util.*;



public class ghidra_prd extends GhidraScript {

    private Address lastAddr = null;
    FidService service;
    TaskMonitor monitor=TaskMonitor.DUMMY;


    @Override
    public void run() throws Exception {
        String [] args = getScriptArgs();
        String name=args[0];
        String outf=args[1];

	    service = new FidService();
        String decompilation=new String();

    	//String name =
    	//	askString("Please enter function name",
    	//		"Please enter the function name you're looking for:");
        println("// Decompiling - "+name);
	    Symbol mangled=find_symbol(name);
        //private Function findFunction(Program program, Address add) {
        Function function = findFunction(currentProgram, mangled.getAddress());
        if ( function == null ){ 
            println("not a valid function name: "+name);
        }
        else {
    	//List<String> called = getCalledPrototypes(function, monitor);
        List<Function> called=getOutgoingCalls(function,monitor);
        called.add(function);
        DecompInterface decomplib = setUpDecompiler(currentProgram);
        
        try {
        	if (!decomplib.openProgram(currentProgram)) {
        		println("Decompile Error: " + decomplib.getLastMessage());
        		return;
        	}

            List<String> protos = getFunctionProtos(decomplib, currentProgram, called);

            decompilation+="//------------------------------------------\n// Function declarations \n\n";
            decompilation+=protos.stream().collect(Collectors.joining("\n"))+"\n\n";
            //println(String.join('\n',protos));
            //println(protos.stream().collect(Collectors.joining("\n"))+"\n\n");
	        decompilation+= get_decompilation(mangled.getAddress().toString(),decompileFunction(function, decomplib));
            println(decompilation);
            FileWriter log=new FileWriter(outf);
            log.write(decompilation);
            log.close();
            

            /*
	        // call decompiler for all refs to current function
	        Symbol sym = this.getSymbolAt(function.getEntryPoint());
	
	        Reference refs[] = sym.getReferences(null);
	
	        for (int i = 0; i < refs.length; i++) {
	            if (monitor.isCancelled()) {
	                break;
	            }
	
	            // get function containing.
	            Address refAddr = refs[i].getFromAddress();
	            Function refFunc = currentProgram.getFunctionManager()
	                    .getFunctionContaining(refAddr);
	
	            if (refFunc == null) {
	                continue;
	            }
	
	            // decompile function
	            // look for call to this function
	            // display call
	            //analyzeFunction(decomplib, currentProgram, refFunc, refAddr);
	        }
            */
        }
        finally {
        	decomplib.dispose();
        }

        lastAddr = null;
        }
    }

    // this looks equivalent to java.util.Set<Function> Function.getCalledFunction(TaskMonitor monitor)
    // looks like prototype can be obtained by 
    //String Function.getPrototypeString(boolean formalSignature, boolean includeCallingConvention)
    private List<String> getCalledPrototypes(Function function, TaskMonitor monitor){
        List<Function> called=getOutgoingCalls(function,monitor);
        List<String> protos= new ArrayList<String>();
        Iterator<Function> it = called.iterator();
        while (it.hasNext()) {
            Function f=it.next();
            String fproto = f.getPrototypeString(true,true);
            println("+ "+fproto);
            protos.add(fproto); 
        }
        println("+ "+(function.getPrototypeString(true,true)));
        return protos;
    }

	private List<Function> getOutgoingCalls(Function function,TaskMonitor monitor) {
        
		//AddressSetView functionBody = function.getBody();
		//Set<Reference> references = getReferencesFrom(currentProgram, functionBody);
		//Set<Function> outgoingFunctions = new HashSet<>();
		//FunctionManager functionManager = currentProgram.getFunctionManager();
		//for (Reference reference : references) {
		//	Address toAddress = reference.getToAddress();
		//	Function calledFunction = functionManager.getFunctionAt(toAddress);
		//	maybeAddIncomingFunction(outgoingFunctions, reference, calledFunction);
		//}
        Set<Function> outgoingFunctions=function.getCalledFunctions(monitor);
		// sort them by address
		List<Function> list = new ArrayList<>(outgoingFunctions);
		Collections.sort(list, (f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));

        return list;
	}

	private void maybeAddIncomingFunction(Set<Function> incomingFunctions, Reference reference,
			Function calledFunction) {
		if (calledFunction != null) {
			incomingFunctions.add(calledFunction);
		}
		else if (isCallReference(reference)) {
			// we have a call reference, but no function
			println("Outgoing function call with no function from " + reference.getFromAddress() +
				" to " + reference.getToAddress());
		}
	}

	private boolean isCallReference(Reference reference) {
		RefType type = reference.getReferenceType();
		if (type.isCall()) {
			return true;
		}

		if (type.isIndirect()) {
			Listing listing = currentProgram.getListing();
			Instruction instruction = listing.getInstructionAt(reference.getFromAddress());
			if (instruction != null) {
				FlowType flowType = instruction.getFlowType();
				return flowType.isCall();
			}
		}

		return false;
	}

	private Set<Reference> getReferencesFrom(Program program, AddressSetView addresses) {
		Set<Reference> set = new HashSet<>();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator addressIterator = addresses.getAddresses(true);
		while (addressIterator.hasNext()) {
			Address address = addressIterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			if (referencesFrom != null) {
				for (Reference reference : referencesFrom) {
					set.add(reference);
				}
			}
		}
		return set;
	}

	private Function getCurrentFunction() {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		return functionManager.getFunctionContaining(currentAddress);
	}

	private Symbol find_symbol(String mangled) {
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();
        Symbol returnme= null;
		while (it.hasNext()) {
			Symbol s = it.next();
    		if (s.getName().equals(mangled)) {
                returnme=s;
                println("Symbol => "+s.getName());
            }
        }
        return returnme;
    }

	private void demangle_symbol_table() {
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();

		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			if (s.getSource() == SourceType.DEFAULT) {
				continue;
			}
			Address addr = s.getAddress();
			String name = s.getName();

			if (name.startsWith("s_") || name.startsWith("u_") || name.startsWith("AddrTable")) {
				continue;
			}

			if (name.indexOf("::case_0x") > 0) {
				int pos = name.indexOf("::case_0x");
				name = name.substring(0, pos);
			}
			else if (name.indexOf("::switchTable") > 0) {
				int pos = name.indexOf("::switchTable");
				name = name.substring(0, pos);
			}

			DemanglerCmd cmd = new DemanglerCmd(addr, name);
			if (!cmd.applyTo(currentProgram, monitor)) {
				println("Unable to demangle: " + s.getName());
			}
		}
	}


    private Function findFunction(Program program, Address add) {
            Function f=null;
    		try {
    			FunctionManager functionManager = program.getFunctionManager();
                f=functionManager.getFunctionAt(add);
    		}
    		catch (Exception e) {
    			Msg.warn(this, "problem looking for " + add.toString(), e);
    		}
            return f;
    }

    private Function findFunction(Program program, String name) {
            Function f=null;
    		try {
    			FunctionManager functionManager = program.getFunctionManager();
    			FunctionIterator functions = functionManager.getFunctions(true);
    			for (Function function : functions) {
                    //println(" - "+function.getName());
    				if (function.getName().equals(name)) {
    					f=function;
    				}

    			}
    		}
    		catch (Exception e) {
    			Msg.warn(this, "problem looking for " + name, e);
    		}
            return f;
    }

    /*
    private void findPrograms(ArrayList<DomainFile> programs, DomainFolder folder)
    		throws VersionException, CancelledException, IOException {
    	DomainFile[] files = folder.getFiles();
    	for (DomainFile domainFile : files) {
    		if (monitor.isCancelled()) {
    			return;
    		}
    		if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
    			programs.add(domainFile);
    		}
    	}
    	DomainFolder[] folders = folder.getFolders();
    	for (DomainFolder domainFolder : folders) {
    		if (monitor.isCancelled()) {
    			return;
    		}
    		findPrograms(programs, domainFolder);
    	}
    }
    private void getFunction(Program program, String name) {
    	try {
    		//program = (Program) domainFile.getDomainObject(this, false, false, monitor);
    		FunctionManager functionManager = program.getFunctionManager();
    		FunctionIterator functions = functionManager.getFunctions(true);
    		for (Function function : functions) {
    			if (monitor.isCancelled()) {
    				return;
    			}
    			if (function.getName().equals(name)) {
    				println("found " + name + " in " + domainFile.getPathname());
    			}
    		}
    	}
    	catch (Exception e) {
    		Msg.warn(this, "problem looking at " + domainFile.getName(), e);
    	}
    }
    */

    private DecompInterface setUpDecompiler(Program program) {
    	DecompInterface decomplib = new DecompInterface();
        
    	DecompileOptions options;
    	options = new DecompileOptions(); 
        /*
    	OptionsService service = state.getTool().getService(OptionsService.class);
    	if (service != null) {
    		ToolOptions opt = service.getOptions("Decompiler");
    		options.grabFromToolAndProgram(null,opt,program);    	
    	}
        decomplib.setOptions(options);
        */
        
    	decomplib.toggleCCode(true);
    	decomplib.toggleSyntaxTree(true);
    	decomplib.setSimplificationStyle("decompile");
		
    	return decomplib;
    }

    /**
     * Analyze a functions references
     */
    public List<String> getFunctionProtos(DecompInterface decomplib, Program prog, List<Function> funcs){
        Iterator<Function> it = funcs.iterator();
        List<String> protos = new ArrayList<String>();
        while (it.hasNext()) {
            Function f=it.next();
            DecompileResults d = decompileFunction(f, decomplib);
            protos.add(d.getDecompiledFunction().getSignature());
        }
        return protos;
        
    }
    /*
    public String analyzeFunction(DecompInterface decomplib, Program prog, Function f, Address refAddr) {
        String s = new String();

        if (f == null) {
            return;
        }

        // don't decompile the function again if it was the same as the last one
        //
        if (!f.getEntryPoint().equals(lastAddr)) {
            s += get_decompilation(refAddr.toString(),decompileFunction(f, decomplib));
        }
        //lastAddr = f.getEntryPoint();

        //Instruction instr = prog.getListing().getInstructionAt(refAddr);
        //if (instr == null) {
        //    return;
        //}

        //println(printCall(f, refAddr));
        return s;
    }
    */



    HighFunction hfunction = null;

    ClangTokenGroup docroot = null;

    public DecompileResults decompileFunction(Function f, DecompInterface decomplib) {

        return decomplib.decompileFunction(f, 5, monitor);
    }

    public void print_decompilation(String info, DecompileResults d){
        println(get_decompilation(info,d));
    }

    public String get_decompilation(String info, DecompileResults d){
        hfunction = d.getHighFunction();
        docroot = d.getCCodeMarkup();
        PrettyPrinter p = new PrettyPrinter(d.getFunction(),docroot);
        DecompiledFunction pretty_d=p.print(true);
        return "\n//----- ("+info+") ------ \n"+pretty_d.getC()+"\n";
    }

    /**
     * get the pcode ops that refer to an address
     */
    public Iterator<PcodeOpAST> getPcodeOps(Address refAddr) {
        if (hfunction == null) {
            return null;
        }
        Iterator<PcodeOpAST> piter = hfunction.getPcodeOps(refAddr.getPhysicalAddress());
        return piter;
    }

    public String printCall(Function f, Address refAddr) {
        StringBuffer buff = new StringBuffer();

        printCall(refAddr, docroot, buff, false, false);

        return buff.toString();
    }

    private boolean printCall(Address refAddr, ClangNode node, StringBuffer buff, boolean didStart, boolean isCall) {
    	if (node == null) {
    		return false;
    	}
    	
    	Address min = node.getMinAddress();
        Address max = node.getMaxAddress();
        if (min == null)
            return false;

        if (refAddr.getPhysicalAddress().equals(max) && node instanceof ClangStatement) {
        	ClangStatement stmt = (ClangStatement) node;
        	// Don't check for an actual call. The call could be buried more deeply.  As long as the original call reference site
        	// is the max address, then display the results.
        	// So this block assumes that the last address contained in the call will be the
        	// address you are looking for.
        	//    - This could lead to strange behavior if the call reference is placed on some address
        	//    that is not the final call point used by the decompiler.
        	//    - Also if there is a delay slot, then the last address for the call reference point
        	//    might not be the last address for the block of PCode.
        	//if (stmt.getPcodeOp().getOpcode() == PcodeOp.CALL) {
	        	if (!didStart) {
	        		Address nodeAddr = node.getMaxAddress();
	        		// Decompiler only knows base space.
	        		//   If reference came from an overlay space, convert address back
	        	    if (refAddr.getAddressSpace().isOverlaySpace()) {
	        	        nodeAddr = refAddr.getAddressSpace().getOverlayAddress(nodeAddr);
	        	    }
	        		buff.append(" " + nodeAddr + "   : ");
	        	}
	        	
	        	buff.append("   " + toString(stmt));
	        	return true;
        	//}
        }
        for (int j = 0; j < node.numChildren(); j++) {
        	isCall = node instanceof ClangStatement;
            didStart |= printCall(refAddr, node.Child(j), buff, didStart, isCall);
        }
        return didStart;
    }

	public String toString(ClangStatement node) {
	    StringBuffer buffer = new StringBuffer();
		int open=-1;
        for (int j = 0; j < node.numChildren(); j++) {
	        ClangNode subNode = node.Child(j);
	        if (subNode instanceof ClangSyntaxToken) {
	        	ClangSyntaxToken syntaxNode = (ClangSyntaxToken) subNode;
	        	if (syntaxNode.getOpen() != -1) {
	        		if (node.Child(j+2) instanceof ClangTypeToken) {
	        			open = syntaxNode.getOpen();
		        		continue;
	        		}
	        	}
	        	if (syntaxNode.getClose() == open && open != -1) {
	        		open = -1;
	        		continue;
	        	}
	        }
        	if (open != -1) {
        		continue;
        	}
	        buffer.append(subNode.toString());
	    }
	    return buffer.toString();
	}
}

