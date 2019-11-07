package org.onosproject.install;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "install-flow-rule",
        description = "install flow rules")
public class FlowRuleInstallCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "conflictFields", description = "",
            required = true, multiValued = false)
    int conflictFields = 0;
    @Argument(index = 1, name = "m", description = "",
            required = false, multiValued = false)
    int m;
    @Argument(index = 2, name = "n", description = "",
            required = false, multiValued = false)
    int n;

    @Override
    protected void doExecute() {
        FlowRuleInstall flowRuleInstallService = AbstractShellCommand.get(FlowRuleInstall.class);
        long start = System.currentTimeMillis();
        flowRuleInstallService.runTest(conflictFields, m, n);
        long end = System.currentTimeMillis();
        System.out.println("FlowRule Install command " + (end - start));
        System.out.println(flowRuleInstallService.getTimes().toString());
    }
}