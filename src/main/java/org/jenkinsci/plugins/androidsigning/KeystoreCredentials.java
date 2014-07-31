package org.jenkinsci.plugins.androidsigning;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.Util;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;

@NameWith(KeystoreCredentials.NameProvider.class)
public interface KeystoreCredentials extends StandardCredentials {
    @Nonnull String getFileName();
    @Nonnull
    InputStream getContent() throws IOException;
    @Nonnull String getPassphrase();

    String getTempPath() throws IOException;

    class NameProvider extends CredentialsNameProvider<KeystoreCredentials> {
        @Override public String getName(KeystoreCredentials c) {
            String description = Util.fixEmptyAndTrim(c.getDescription());
            return c.getFileName() + (description != null ? " (" + description + ")" : "");
        }
    }
}
