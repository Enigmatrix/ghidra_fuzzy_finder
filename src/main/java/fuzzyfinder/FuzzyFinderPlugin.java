package fuzzyfinder;


import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "FuzzyFinder",
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Fuzzy finder for Ghidra",
	description = "Fuzzy finder for finding symbols, functions and labels in Ghidra"
)
//@formatter:on
public class FuzzyFinderPlugin extends ProgramPlugin {

	public static String NAME = "Fuzzy Find";

	public FuzzyFinderPlugin(PluginTool tool) {
		super(tool, true, true);

		var triggerAction = new DockingAction(NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "Hello World!");
			}
		};
		triggerAction.setEnabled(true);
		triggerAction.setMenuBarData(new MenuData(new String[] { PluginCategoryNames.NAVIGATION, NAME}));

		tool.addAction(triggerAction);
	}


}
