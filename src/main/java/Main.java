import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.*;
import org.apache.jackrabbit.core.TransientRepository;

import javax.jcr.*;
import java.io.File;
import java.lang.reflect.Method;

public class Main {

    private static final String DEFAULT_USER_ADMIN_GROUP_NAME = "UserAdmin";

    public static void main(String[] args) throws Exception {

        Repository repository = new TransientRepository(new File("jackrabbitPath"));
        Session session = repository.login(new SimpleCredentials("admin", "admin".toCharArray()));

        changePassword(session, "admin", "admin", "password", "password");
    }

    public static User changePassword(Session jcrSession,
                               String name,
                               String oldPassword,
                               String newPassword,
                               String newPasswordConfirm)
            throws Exception
    {
        if ("anonymous".equals(name)) {
            throw new RepositoryException(
                    "Can not change the password of the anonymous user.");
        }

        User user;
        UserManager userManager = ((JackrabbitSession)jcrSession).getUserManager();
        Authorizable authorizable = userManager.getAuthorizable(name);
        if (authorizable instanceof User) {
            user = (User)authorizable;

        } else {
            throw new Exception("User to update could not be determined");
        }

        //SLING-2069: if the current user is an administrator, then a missing oldPwd is ok,
        // otherwise the oldPwd must be supplied.
        boolean administrator = false;

        // check that the submitted parameter values have valid values.
        if (oldPassword == null || oldPassword.length() == 0) {
            try {
                UserManager um = ((JackrabbitSession)jcrSession).getUserManager();
                User currentUser = (User) um.getAuthorizable(jcrSession.getUserID());
                administrator = currentUser.isAdmin();

                if (!administrator) {
                    //check if the user is a member of the 'User administrator' group
                    Authorizable userAdmin = um.getAuthorizable(DEFAULT_USER_ADMIN_GROUP_NAME);
                    if (userAdmin instanceof Group) {
                        boolean isMember = ((Group)userAdmin).isMember(currentUser);
                        if (isMember) {
                            administrator = true;
                        }
                    }

                }
            } catch ( Exception ex ) {
                //log.warn("Failed to determine if the user is an admin, assuming not. Cause: "+ex.getMessage());
                administrator = false;
            }
            if (!administrator) {
                throw new RepositoryException("Old Password was not submitted");
            }
        }
        if (newPassword == null || newPassword.length() == 0) {
            throw new RepositoryException("New Password was not submitted");
        }
        if (!newPassword.equals(newPasswordConfirm)) {
            throw new RepositoryException(
                    "New Password does not match the confirmation password");
        }

        if (oldPassword != null && oldPassword.length() > 0) {
            // verify old password
            checkPassword(authorizable, oldPassword);
        }

        try {
            ((User) authorizable).changePassword(newPassword);

        } catch (RepositoryException re) {
            throw new RepositoryException("Failed to change user password.", re);
        }

        return user;
    }

    private static void checkPassword(Authorizable authorizable, String oldPassword)
            throws RepositoryException {
        Credentials oldCreds = ((User) authorizable).getCredentials();
        if (oldCreds instanceof SimpleCredentials) {
            char[] oldCredsPwd = ((SimpleCredentials) oldCreds).getPassword();
            if (oldPassword.equals(String.valueOf(oldCredsPwd))) {
                return;
            }
        } else {
            try {
                // CryptSimpleCredentials.matches(SimpleCredentials credentials)
                Class<?> oldCredsClass = oldCreds.getClass();
                Method matcher = oldCredsClass.getMethod("matches",
                        SimpleCredentials.class);
                SimpleCredentials newCreds = new SimpleCredentials(
                        authorizable.getPrincipal().getName(),
                        oldPassword.toCharArray());
                boolean match = (Boolean) matcher.invoke(oldCreds, newCreds);
                if (match) {
                    return;
                }
            } catch (Throwable t) {
                // failure here, fall back to password check failure below
            }
        }

        throw new RepositoryException("Old Password does not match");
    }
}
