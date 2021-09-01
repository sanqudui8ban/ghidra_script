import java.util.HashMap;
import java.util.Map;

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
/**
 * Example script for creating and displaying a graph in ghidra
 */
public class ExampleGraphServiceScript extends GhidraScript {
	private AttributedGraph graph = new AttributedGraph();
	private int nextEdgeID = 1;
	private HighFunction high;
	private Function func; 
	private Map<String, AttributedVertex> avMap = new HashMap();
	
	
	
	@Override
	protected void run() throws Exception {
		PluginTool tool = getState().getTool();
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		GraphDisplay display = service.getDefaultGraphDisplay(false, monitor);
		display.defineVertexAttribute("kp");
		display.setVertexLabelAttribute("kp", GraphDisplay.ALIGN_LEFT, 8, true, 5000);
		buildAST();
		generateGraph();
		display.setGraph(graph, "Test", false, monitor);
		
	}

	private void generateGraph() {

		java.util.ArrayList<PcodeBlockBasic> listPBB = high.getBasicBlocks();
		for(int i = 0; i < listPBB.size(); i++)
		{
			createVertexFromBasicBlock(listPBB.get(i));
		}
		
		for(int j = 0; j < listPBB.size(); j++)
		{
			createEdge(listPBB.get(j));
		}
		
		
		
	}
	
	public void createEdge(PcodeBlockBasic pbb)
	{
		int outSize = pbb.getOutSize();
		AttributedVertex base = avMap.get(String.valueOf(pbb.getStart().getOffset()));
		for(int i = 0; i < outSize; i++)
		{
			PcodeBlock pb = pbb.getOut(i);
			AttributedVertex out = avMap.get(String.valueOf(pb.getStart().getOffset()));
			edge(base, out);
			System.out.println(String.format("base:%016x out:%016x", pbb.getStart().getOffset(), pb.getStart().getOffset()));
		}
		
	}
	
	private void buildAST() throws DecompileException {
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);

		if (!ifc.openProgram(this.currentProgram)) {
			throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
		}
		//ifc.setSimplificationStyle("normalize");
		func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			throw new DecompileException( "GraphAST Error", "No Function at current location");
		}
		DecompileResults res = ifc.decompileFunction(func, 30, null);
		high = res.getHighFunction();

	}
	
	private AttributedVertex createVertexFromBasicBlock(PcodeBlockBasic pbb)
	{
		StringBuilder sb = new StringBuilder();
		ghidra.program.model.address.Address beginAddress = pbb.getStart();
		String beginStr = String.valueOf(beginAddress.getOffset());
		if(avMap.containsKey(beginStr) == false)
		{
			sb.append(new String().format("%016x~%016x\n", beginAddress.getOffset(), pbb.getStop().getOffset()));
			java.util.Iterator<PcodeOp> itPcode = pbb.getIterator();
			while(itPcode.hasNext()) {
	            PcodeOp po = itPcode.next();
	            sb.append(po.toString() + "\n");
	        }
			
			String id = String.valueOf(beginAddress.getOffset());
			String name = String.valueOf(beginAddress.getOffset());
			AttributedVertex av = vertex(id, name);
			av.setAttribute("kp", sb.toString());
			avMap.put(beginStr, av);
			return av;
		}
		
		return null;
		
	}
	
	
	private AttributedVertex vertex(String name) {
		return graph.addVertex(name, name);
	}
	
	private AttributedVertex vertex(String id, String name) {
		return graph.addVertex(id, name);
	}

	private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
		return graph.addEdge(v1, v2);
	}

}
