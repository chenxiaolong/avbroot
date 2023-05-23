import android.annotation.SuppressLint;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Process;
import android.system.ErrnoException;

import java.lang.reflect.Method;

@SuppressLint({"DiscouragedPrivateApi", "PrivateApi", "SoonBlockedPrivateApi"})
public class Main {
    private static final int GET_SERVICE_ATTEMPTS = 30;

    @SuppressWarnings("SameParameterValue")
    private static IInterface getService(Class<?> interfaceClass, String serviceName) throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod("getService", String.class);

        Class<?> stub = Class.forName(interfaceClass.getCanonicalName() + "$Stub");
        Method asInterface = stub.getDeclaredMethod("asInterface", IBinder.class);

        // ServiceManager.waitForService() tries to start the service, which we want to avoid to be
        // 100% sure we're not disrupting the boot flow.
        for (int attempt = 1; attempt <= GET_SERVICE_ATTEMPTS; ++attempt) {
            IBinder iBinder = (IBinder) getService.invoke(null, serviceName);
            if (iBinder != null) {
                return (IInterface) asInterface.invoke(null, iBinder);
            }

            if (attempt < GET_SERVICE_ATTEMPTS) {
                Thread.sleep(1000);
            }
        }

        throw new IllegalStateException(
                "Service " + serviceName + " not found after " + GET_SERVICE_ATTEMPTS + " attempts");
    }

    @SuppressWarnings("ConstantConditions")
    private static void unlock() throws Exception {
        Class<?> iOemLockService = Class.forName("android.service.oemlock.IOemLockService");
        IInterface iFace = getService(iOemLockService, "oem_lock");

        Method setOemUnlockAllowedByUser = iOemLockService.getDeclaredMethod("setOemUnlockAllowedByUser", boolean.class);
        Method isOemUnlockAllowedByUser = iOemLockService.getDeclaredMethod("isOemUnlockAllowedByUser");

        Boolean unlockAllowed = (Boolean) isOemUnlockAllowedByUser.invoke(iFace);
        if (unlockAllowed) {
            System.out.println("OEM unlocking already enabled");
            return;
        }

        System.out.println("Enabling OEM unlocking");
        setOemUnlockAllowedByUser.invoke(iFace, true);
    }

    @SuppressWarnings({"ConstantConditions", "JavaReflectionMemberAccess"})
    private static void switchToSystemUid() throws Exception {
        if (Process.myUid() != Process.SYSTEM_UID) {
            Method setUid = Process.class.getDeclaredMethod("setUid", int.class);
            int errno = (int) setUid.invoke(null, Process.SYSTEM_UID);

            if (errno != 0) {
                throw new Exception("Failed to switch to SYSTEM (" + Process.SYSTEM_UID + ") user",
                        new ErrnoException("setuid", errno));
            }
            if (Process.myUid() != Process.SYSTEM_UID) {
                throw new IllegalStateException("UID didn't actually change: " +
                        Process.myUid() + " != " + Process.SYSTEM_UID);
            }
        }
    }

    public static void main(String[] args) {
        try {
            switchToSystemUid();
            unlock();
        } catch (Exception e) {
            System.err.println("Failed to enable OEM unlocking");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
