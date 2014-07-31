package org.jenkinsci.plugins.androidsigning;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

public final class Entry extends AbstractDescribableImpl<Entry> {
    private String keyStore;
    private String alias;
    private String selection;

    @DataBoundConstructor
    public Entry(String keyStore, String alias, String selection) {
        this.keyStore = keyStore;
        this.alias = alias;
        this.selection = selection;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<Entry> {
        @Override
        public String getDisplayName() {
            return ""; // unused
        }
    }

    public String getSelection() {
        return selection;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public String getAlias() {
        return alias;
    }
}
