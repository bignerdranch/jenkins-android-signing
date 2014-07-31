package org.jenkinsci.plugins.androidsigning;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Proc;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Result;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import hudson.util.ArgumentListBuilder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.lang.ArrayUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

public class SignArtifactPlugin extends Recorder {

    private List<Entry> entries = Collections.emptyList();

    @DataBoundConstructor
    public SignArtifactPlugin(List<Entry> rpms) {
        this.entries = rpms;
        if (this.entries == null) {
            this.entries = Collections.emptyList();
        }
    }

    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }

    private boolean isPerformDeployment(AbstractBuild build) {
        Result result = build.getResult();
        if (result == null) {
            return true;
        }

        return build.getResult().isBetterOrEqualTo(Result.UNSTABLE);
    }

    @SuppressWarnings("unused")
    public List<Entry> getEntries() {
        return entries;
    }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
        if (isPerformDeployment(build)) {
            listener.getLogger().println("[RpmSignPlugin] - Starting signing RPMs ...");

            for (Entry rpmEntry : entries) {
                StringTokenizer rpmGlobTokenizer = new StringTokenizer(rpmEntry.getSelection(), ",");
                KeystoreCredentials keystore = getKeystore(rpmEntry.getKeyStore());
                while (rpmGlobTokenizer.hasMoreTokens()) {
                    String rpmGlob = rpmGlobTokenizer.nextToken();

                    listener.getLogger().println("[AndroidSignPlugin] - Publishing " + rpmGlob);

                    FilePath[] matchedRpms = build.getWorkspace().list(rpmGlob);
                    if (ArrayUtils.isEmpty(matchedRpms)) {
                        listener.getLogger().println("[AndroidSignPlugin] - No APKs matching " + rpmGlob);
                    } else {
                        for (FilePath rpmFilePath : matchedRpms) {
                            ArgumentListBuilder rpmSignCommand = new ArgumentListBuilder();

                            //jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my_application.apk alias_name
                            rpmSignCommand.add("jarsigner", "-verbose");
                            rpmSignCommand.add("-sigalg", "SHA1withRSA");
                            rpmSignCommand.add("-digestalg", "SHA1");
                            rpmSignCommand.add("-keystore", keystore.getTempPath());
                            rpmSignCommand.add(rpmFilePath.toURI().normalize().getPath());
                            rpmSignCommand.add(rpmEntry.getAlias());

                            String rpmCommandLine = rpmSignCommand.toString();
                            listener.getLogger().println("[RpmSignPlugin] - Running " + rpmCommandLine);

                            ArgumentListBuilder expectCommand = new ArgumentListBuilder();
                            expectCommand.add("expect", "-");

                            Launcher.ProcStarter ps = launcher.new ProcStarter();
                            ps = ps.cmds(expectCommand).stdout(listener);
                            ps = ps.pwd(build.getWorkspace()).envs(build.getEnvironment(listener));

                            byte[] expectScript = createExpectScriptFile(rpmCommandLine, keystore.getPassphrase());
                            ByteArrayInputStream is = new ByteArrayInputStream(expectScript);
                            ps.stdin(is);

                            Proc proc = launcher.launch(ps);
                            int retcode = proc.join();
                            if (retcode != 0) {
                                listener.getLogger().println("[AndroidSignPlugin] - Failed signing APKs ...");
                                return false;
                            }
                        }

                    }
                }
            }

            listener.getLogger().println("[AndroidSignPlugin] - Finished signing APKs ...");
        } else {
            listener.getLogger().println("[AndroidSignPlugin] - Skipping signing APKs ...");
        }
        return true;
    }

    private KeystoreCredentials getKeystore(String keyStoreName) {
        List<KeystoreCredentials> creds = CredentialsProvider.lookupCredentials(KeystoreCredentials.class, Jenkins.getInstance(), ACL.SYSTEM);
        for(KeystoreCredentials cred : creds) {
            if(cred.getId().equals(keyStoreName)){
                return cred;
            }
        }
        return null;
    }

    private byte[] createExpectScriptFile(String signCommand, String passphrase)
            throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(512);

        final PrintWriter writer = new PrintWriter(new OutputStreamWriter(baos));
        try {
            writer.print("spawn ");
            writer.println(signCommand);
            writer.println("expect \"Enter pass phrase: \"");
            writer.print("send -- \"");
            writer.print(passphrase);
            writer.println("\r\"");
            writer.println("expect eof");
            writer.println("catch wait rc");
            writer.println("exit [lindex $rc 3]");
            writer.println();

            writer.flush();
        } finally {
            writer.close();
        }

        return baos.toByteArray();
    }


    @Extension
    @SuppressWarnings("unused")
    public static final class GpgSignerDescriptor extends BuildStepDescriptor<Publisher> {

        public static final String DISPLAY_NAME = Messages.job_displayName();

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        public GpgSignerDescriptor() {
            load();
        }

        @Override
        public String getDisplayName() {
            return DISPLAY_NAME;
        }

        public ListBoxModel doFillKeyStoreItems() {
            ListBoxModel items = new ListBoxModel();
            for (KeystoreCredentials gpgKey : CredentialsProvider.lookupCredentials(KeystoreCredentials.class, Jenkins.getInstance(), ACL.SYSTEM)) {
                items.add(gpgKey.getDescription(), gpgKey.getId());
            }
            return items;
        }

        public FormValidation doCheckName(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckPrivateKey(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckPassphrase(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckIncludes(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException, InterruptedException {
            if (project.getSomeWorkspace() != null) {
                String msg = project.getSomeWorkspace().validateAntFileMask(value);
                if (msg != null) {
                    return FormValidation.error(msg);
                }
                return FormValidation.ok();
            } else {
                return FormValidation.warning(Messages.noworkspace());
            }
        }

    }

}
