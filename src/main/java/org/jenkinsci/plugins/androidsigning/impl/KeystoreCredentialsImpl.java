package org.jenkinsci.plugins.androidsigning.impl;

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.FilePath;
import hudson.util.IOException2;
import hudson.util.Secret;
import jenkins.security.CryptoConfidentialKey;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.fileupload.FileItem;
import org.jenkinsci.plugins.androidsigning.KeystoreCredentials;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.io.*;
import java.security.GeneralSecurityException;


public class KeystoreCredentialsImpl extends BaseStandardCredentials implements KeystoreCredentials{
    private static final CryptoConfidentialKey KEY = new CryptoConfidentialKey(KeystoreCredentialsImpl.class.getName());

    private final @Nonnull Secret passphrase;
    private final @Nonnull String fileName;
    private final @Nonnull byte[] data;

    @DataBoundConstructor
    public KeystoreCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id, @CheckForNull String description, @Nonnull FileItem file, @CheckForNull String fileName, @CheckForNull String data, @CheckForNull String passphrase) throws IOException {
        super(scope, id, description);
        String name = file.getName();
        if (name.length() > 0) {
            this.fileName = name.replaceFirst("^.+[/\\\\]", "");
            byte[] unencrypted = file.get();
            try {
                this.data = KEY.encrypt().doFinal(unencrypted);
            } catch (GeneralSecurityException x) {
                throw new IOException2(x);
            }
        } else {
            this.fileName = fileName;
            this.data = Base64.decodeBase64(data);
        }
        this.passphrase = Secret.fromString(passphrase);
    }

    public FilePath makeTempPath(FilePath path) throws IOException, InterruptedException {
        FilePath tmp = path.createTempFile("keystore", null);
        OutputStream out = tmp.write();
        out.write(unencrypted());
        out.close();
        return tmp;
    }

    public String getFileName() {
        return fileName;
    }

    public InputStream getContent() throws IOException {
        return new ByteArrayInputStream(unencrypted());
    }

    public String getPassphrase() {
        return passphrase.getPlainText();
    }

    private byte[] unencrypted() throws IOException {
        try {
            return KEY.decrypt().doFinal(data);
        } catch (GeneralSecurityException x) {
            throw new IOException2(x);
        }
    }

    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        @Override public String getDisplayName() {
            return Messages.KeystoreCredentialsImpl_keystore();
        }

    }
}