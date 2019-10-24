package org.onosproject.install;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "install-FlowRule",
        description = "install flow rules")
public class FlowRuleInstallCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "mac", description = "One Mac Address",
            required = false, multiValued = false)
    String mac = null;

    @Override
    protected void doExecute() {
        FlowRuleInstall flowRuleInstallService = AbstractShellCommand.get(FlowRuleInstall.class);

    }
}