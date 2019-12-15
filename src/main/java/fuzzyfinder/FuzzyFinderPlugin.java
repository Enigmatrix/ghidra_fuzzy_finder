package fuzzyfinder;


import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "FuzzyFinder",
	category = Info.CATEGORY,
	shortDescription = "Fuzzy finder for Ghidra",
	description = "Fuzzy finder for finding symbols, functions and labels in Ghidra",
	servicesRequired = { GoToService.class, ProgramManager.class },
	eventsConsumed =  { ProgramActivatedPluginEvent.class, ProgramClosedPluginEvent.class, ProgramOpenedPluginEvent.class}
)
//@formatter:on
public class FuzzyFinderPlugin extends ProgramPlugin {

	private FuzzyFinderDialog dialog;

	public FuzzyFinderPlugin(PluginTool tool) {
		super(tool, true, true, true);

		dialog = new FuzzyFinderDialog(this);

		var triggerAction = new DockingAction(Info.NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				dialog.show();
			}
		};
		triggerAction.setMenuBarData(new MenuData(new String[] { Info.CATEGORY, Info.NAME }));
		triggerAction.setEnabled(true);

		tool.addAction(triggerAction);
	}

	public Program[] getOpenedPrograms() {
		var pm = tool.getService(ProgramManager.class);
		return pm.getAllOpenPrograms();
	}
}
