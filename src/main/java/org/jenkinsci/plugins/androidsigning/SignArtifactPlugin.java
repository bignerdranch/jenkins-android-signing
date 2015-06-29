package org.jenkinsci.plugins.androidsigning;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Proc;
import hudson.model.*;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Publisher;
import hudson.util.ArgumentListBuilder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.*;
import java.util.*;

public class SignArtifactPlugin extends Publisher {

    private List<Apk> entries = Collections.emptyList();

    @DataBoundConstructor
    public SignArtifactPlugin(List<Apk> apks) {
        this.entries = apks;
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
    public List<Apk> getEntries() {
        return entries;
    }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
        if (isPerformDeployment(build)) {
            for (Apk entry : entries) {
                StringTokenizer rpmGlobTokenizer = new StringTokenizer(entry.getSelection(), ",");
                KeystoreCredentials keystore = getKeystore(entry.getKeyStore());
                listener.getLogger().println("[AndroidSignPlugin] - Signing " + rpmGlobTokenizer.countTokens() + " APKs");
                while (rpmGlobTokenizer.hasMoreTokens()) {
                    String rpmGlob = rpmGlobTokenizer.nextToken();

                    FilePath[] matchedApks = build.getWorkspace().list(rpmGlob);
                    if (ArrayUtils.isEmpty(matchedApks)) {
                        listener.getLogger().println("[AndroidSignPlugin] - No APKs matching " + rpmGlob);
                    } else {
                        for (FilePath rpmFilePath : matchedApks) {

                            ArgumentListBuilder apkSignCommand = new ArgumentListBuilder();
                            String cleanPath = rpmFilePath.toURI().normalize().getPath();
                            String signedPath = cleanPath.replace("unsigned", "signed");
                            String alignedPath = signedPath.replace("signed", "signed-aligned");
                            FilePath key = keystore.makeTempPath(build.getWorkspace());

                            //jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my_application.apk alias_name
                            apkSignCommand.add("jarsigner");
                            apkSignCommand.add("-sigalg", "SHA1withRSA");
                            apkSignCommand.add("-digestalg", "SHA1");
                            apkSignCommand.add("-keystore", key.getRemote());
                            apkSignCommand.add("-storepass");
                            apkSignCommand.addMasked(keystore.getPassphrase());
                            apkSignCommand.add("-signedjar", signedPath);
                            apkSignCommand.add(cleanPath);
                            apkSignCommand.add(entry.getAlias());

                            listener.getLogger().println("[AndroidSignPlugin] - Signing on " + Computer.currentComputer().getDisplayName());

                            Launcher.ProcStarter ps = launcher.new ProcStarter();
                            ps = ps.cmds(apkSignCommand).stdout(listener);
                            ps = ps.pwd(rpmFilePath.getParent()).envs(build.getEnvironment(listener));
                            Proc proc = launcher.launch(ps);

                            int retcode = proc.join();
                            key.delete();
                            if (retcode != 0) {
                                listener.getLogger().println("[AndroidSignPlugin] - Failed signing APK");
                                return false;
                            }

                            Map<String,String> artifactsInsideWorkspace = new LinkedHashMap<String,String>();
                            artifactsInsideWorkspace.put(signedPath, stripWorkspace(build.getWorkspace(), signedPath));


                            ///opt/android-sdk/build-tools/20.0.0/zipalign
                            String zipalign = build.getEnvironment(listener).get("ANDROID_ZIPALIGN");
                            if(zipalign == null || StringUtils.isEmpty(zipalign)){
                                throw new RuntimeException("You must set the environmental variable ANDROID_ZIPALIGN to point to the correct binary");
                            }
                            ArgumentListBuilder zipalignCommand = new ArgumentListBuilder();
                            zipalignCommand.add(zipalign);
                            zipalignCommand.add("4");
                            zipalignCommand.add(signedPath);
                            zipalignCommand.add(alignedPath);

                            Launcher.ProcStarter ps2 = launcher.new ProcStarter();
                            ps2 = ps2.cmds(zipalignCommand).stdout(listener);
                            ps2 = ps2.pwd(rpmFilePath.getParent()).envs(build.getEnvironment(listener));
                            Proc proc2 = launcher.launch(ps2);
                            retcode = proc2.join();
                            if(retcode != 0) {
                                listener.getLogger().println("[AndroidSignPlugin] - Failed aligning APK");
                                return true;
                            }
                            artifactsInsideWorkspace.put(alignedPath, stripWorkspace(build.getWorkspace(), alignedPath));
                            build.pickArtifactManager().archive(build.getWorkspace(), launcher, listener, artifactsInsideWorkspace);
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

    private String stripWorkspace(FilePath ws, String path) {
        return path.replace(ws.getRemote(), "");
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

    @Extension
    @SuppressWarnings("unused")
    public static final class SignArtifactDescriptor extends BuildStepDescriptor<Publisher> {

        public static final String DISPLAY_NAME = Messages.job_displayName();

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        public SignArtifactDescriptor() {
            super();
            load();
        }

        @Override
        public String getDisplayName() {
            return DISPLAY_NAME;
        }

        public ListBoxModel doFillKeystoreItems() {
            ListBoxModel items = new ListBoxModel();
            for (KeystoreCredentials gpgKey : CredentialsProvider.lookupCredentials(KeystoreCredentials.class, Jenkins.getInstance(), ACL.SYSTEM)) {
                items.add(gpgKey.getDescription(), gpgKey.getId());
            }
            return items;
        }

        public FormValidation doCheckAlias(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckSelection(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException, InterruptedException {
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
