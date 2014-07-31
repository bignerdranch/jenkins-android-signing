package org.jenkinsci.plugins.androidsigning;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

public final class Apk extends AbstractDescribableImpl<Apk> {
    private String keyStore;
    private String alias;
    private String selection;

    @DataBoundConstructor
    public Apk(String keystore, String alias, String selection) {
        this.keyStore = keystore;
        this.alias = alias;
        this.selection = selection;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<Apk> {
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
