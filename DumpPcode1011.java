//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.HashMap;
import java.util.Map;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.service.graph.*;
import ghidra.program.model.listing.Function;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;

public class DumpPcode1011 extends GhidraScript {


    private int nextEdgeID = 1;
    private HighFunction high;
    private Function func; 
    private Map<String, String> avMap = new HashMap();
    private File f;
    private PrintWriter ia;
    
    
    
    @Override
    protected void run() throws Exception {
      try
      {
    println("haha1");
        f = new File("C:\\Users\\chai.peng\\Desktop\\pcode.bin");
        ia = new PrintWriter(f);
        if(f.exists())
        {
          f.delete();

        }
        f.createNewFile();

        buildAST();
        generateGraph();
        //generateAstGraph();
        ia.close();
      }catch(Exception e)
      {
    println(e.getMessage());
        e.printStackTrace();
      }
      
      
    }

    private void generateGraph() {

      java.util.ArrayList<PcodeBlockBasic> listPBB = high.getBasicBlocks();
      for(int i = 0; i < listPBB.size(); i++)
      {
        printBasicBlock(listPBB.get(i));
      }
      
      
    }
    
    protected Iterator<PcodeOpAST> getPcodeOpIterator() {
      Iterator<PcodeOpAST> opiter = high.getPcodeOps();
      return opiter;
    }

    private void generateAstGraph() {
      Map<String, String> addrMap = new HashMap();

      Iterator<PcodeOpAST> opiter = getPcodeOpIterator();
      while (opiter.hasNext()) {
        PcodeOpAST op = opiter.next();
        String beginStr = String.valueOf(op.getParent().getStart().getOffset());
        
        if(!addrMap.containsKey(beginStr))
        {
          ia.println(new String().format("%016x~%016x:", op.getParent().getStart().getOffset(), op.getParent().getStop().getOffset()));
          addrMap.put(beginStr, beginStr);
        }
        
        ia.println(op.toString());
      }
      
    }

    
    private void buildAST() throws DecompileException {
      DecompileOptions options = new DecompileOptions();
      DecompInterface ifc = new DecompInterface();
      ifc.setOptions(options);
      

      if (!ifc.openProgram(this.currentProgram)) {
        throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
      }
      //ifc.setSimplificationStyle("normal");
      func = this.getFunctionContaining(this.currentAddress);
      if (func == null) {
        throw new DecompileException( "GraphAST Error", "No Function at current location");
      }
      DecompileResults res = ifc.decompileFunction(func, 30, null);
      high = res.getHighFunction();

    }


    
    private void printBasicBlock(PcodeBlockBasic pbb)
    {
      //println("haha2");
      StringBuilder sb = new StringBuilder();
      ghidra.program.model.address.Address beginAddress = pbb.getStart();
      String beginStr = String.valueOf(beginAddress.getOffset());
      //if(avMap.containsKey(beginStr) == false)
      //{
        sb.append(new String().format("%08x~%08x\n", beginAddress.getOffset(), pbb.getStop().getOffset()));
        sb.append("in:");
        java.util.Iterator<PcodeOp> itPcode = pbb.getIterator();
        //println("haha3");
        for (int i = 0; i < pbb.getInSize() ; i++ ) {

          long inOffset = pbb.getIn(i).getStart().getOffset();
          sb.append(new String().format("%08x,", inOffset));
        }
        sb.append("\n");
        //println("haha4");
        while(itPcode.hasNext()) {
                PcodeOp po = itPcode.next();
                sb.append(po.getSeqnum().toString()+":"+po.toString() + "\n");
        }

        if(pbb.getOutSize() >= 2)
        {
          sb.append(new String().format("true out:%08x false out:%08x\n", pbb.getTrueOut().getStart().getOffset(), pbb.getFalseOut().getStart().getOffset()));
        }
        else if(pbb.getOutSize() == 1)
        {
          //println("haha5");
          sb.append(new String().format("out:%08x\n", pbb.getOut(0).getStart().getOffset()));
        }
        

        avMap.put(beginStr, beginStr);
        ia.println(sb.toString());
        //println(sb.toString());
        //return;
      //}
      
      return;
      
    }
    
    
  
}
