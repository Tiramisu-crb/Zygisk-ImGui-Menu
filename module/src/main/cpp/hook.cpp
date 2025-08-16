#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <cstdlib>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include "imgui.h"
#include "imgui_internal.h"
#include "backends/imgui_impl_opengl3.h"
#include "backends/imgui_impl_android.h"
#include "KittyMemory/KittyMemory.h"
#include "KittyMemory/MemoryPatch.h"
#include "KittyMemory/KittyScanner.h"
#include "KittyMemory/KittyUtils.h"
#include "Includes/Dobby/dobby.h"
#include "Include/Unity.h"
#include "Misc.h"
#include "hook.h"
#include "Include/Roboto-Regular.h"
#include <iostream>
#include <chrono>
#include "Include/Quaternion.h"
#include "Rect.h"
#include <limits>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <limits.h>

#define GamePackageName "com.igenesoft.hide" // define the game package name here please

int glHeight, glWidth;

int isGame(JNIEnv *env, jstring appDataDir)
{
    if (!appDataDir) return 0;

    const char *app_data_dir = env->GetStringUTFChars(appDataDir, nullptr);
    int user = 0;
    static char package_name[256];
    if (sscanf(app_data_dir, "/data/%*[^/]/%d/%s", &user, package_name) != 2) {
        if (sscanf(app_data_dir, "/data/%*[^/]/%s", package_name) != 1) {
            package_name[0] = '\0';
            LOGW(OBFUSCATE("can't parse %s"), app_data_dir);
            env->ReleaseStringUTFChars(appDataDir, app_data_dir);
            return 0;
        }
    }

    if (strcmp(package_name, GamePackageName) == 0) {
        LOGI(OBFUSCATE("detect game: %s"), package_name);
        game_data_dir = new char[strlen(app_data_dir) + 1];
        strcpy(game_data_dir, app_data_dir);
        env->ReleaseStringUTFChars(appDataDir, app_data_dir);
        return 1;
    }

    env->ReleaseStringUTFChars(appDataDir, app_data_dir);
    return 0;
}

const char *sensitiveStrings[] = {
    "/su", "superuser", "magisk", "topjohnwu",
    "luckypatcher", "chelpus", "Kinguser",
    "supersu", "busybox", "kernelsu", "daemonsu",
    "/proc/self/attr/prev", "bstfolder", "libmaa.so",
    "/root", "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hostname",
    "/etc/network/", "/etc/hosts", "/etc/systemd/", "/etc/rc.local",
    "/boot/", "/proc/kcore", "/proc/cpuinfo", "/proc/meminfo",
    "/proc/self/", "/proc/sys/", "/proc/sys/kernel/", "/sys/kernel/security/",
    "/dev/", "/data/data/com.android", "/system/app/", "/system/xbin/",
    "/system/bin/", "/sbin/", "/.ssh/", "/var/log/", "/tmp/", "/var/tmp/",
    "/lib/modules/", "/lib64/", "/usr/local/bin/", "/usr/bin/", "/bin/",
    "/var/crash/", "/var/log/lastlog", "/sys/class/mem", "/sys/class/power_supply",
    "/sys/devices/system/cpu/", "/sys/kernel/debug/", "/proc/partitions",
    "libxposed.so", "anti_cheat", "game_guardian", "libinput.so"
};

static int contains_sensitive(const char *path) {
    for (int i = 0; i < sizeof(sensitiveStrings)/sizeof(*sensitiveStrings); i++) {
        if (strstr(path, sensitiveStrings[i])) return 1;
    }
    return 0;
}

HOOKAF(char*, getprop_hook, const char *name) {
    if (contains_sensitive(name) || strstr(name, "ro.build.type") || strstr(name, "ro.debuggable")) {
        return const_cast<char*>("user");
    }
    return origgetprop_hook(name);
}

HOOKAF(int, access_hook, const char *filename, int mode) {
    CHECK_PATH_ORIGINAL(origaccess_hook, filename, mode);
}

HOOKAF(FILE*, fopen_hook, const char *fname, const char *mode) {
    CHECK_PATH_ORIGINAL(origfopen_hook, fname, mode);
}

HOOKAF(int, stat_hook, const char *pathname, struct stat *statbuf) {
    CHECK_PATH_ORIGINAL(origstat_hook, pathname, statbuf);
}

HOOKAF(int, lstat_hook, const char *pathname, struct stat *statbuf) {
    CHECK_PATH_ORIGINAL(origlstat_hook, pathname, statbuf);
}

HOOKAF(int, fstat_hook, int fd, struct stat *statbuf) {
    char filepath[256];
    char realPathBuf[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "/proc/self/fd/%d", fd);
    if (realpath(filepath, realPathBuf) && contains_sensitive(realPathBuf)) {
        memset(statbuf, 0, sizeof(struct stat));
        errno = ENOENT;
        return -1;
    }
    return origfstat_hook(fd, statbuf);
}

HOOKAF(int, open_hook, const char *pathname, int flags, mode_t mode) {
    CHECK_PATH_ORIGINAL(origopen_hook, pathname, flags, mode);
}

HOOKAF(off_t, lseek_hook, int fd, off_t offset, int whence) {
    char filepath[256];
    char realPathBuf[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "/proc/self/fd/%d", fd);
    if (realpath(filepath, realPathBuf) && contains_sensitive(realPathBuf)) {
        return -1;
    }
    return origlseek_hook(fd, offset, whence);
}

HOOKAF(ssize_t, read_hook, int fd, void *buf, size_t count) {
    char filepath[256];
    char realPathBuf[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "/proc/self/fd/%d", fd);
    if (realpath(filepath, realPathBuf) && contains_sensitive(realPathBuf)) {
        errno = EACCES;
        return -1;
    }
    return origread_hook(fd, buf, count);
}

HOOKAF(ssize_t, write_hook, int fd, const void *buf, size_t count) {
    char filepath[256];
    char realPathBuf[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "/proc/self/fd/%d", fd);
    if (realpath(filepath, realPathBuf) && contains_sensitive(realPathBuf)) {
        errno = EACCES;
        return -1;
    }
    return origwrite_hook(fd, buf, count);
}

HOOKAF(void*, mmap_hook, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    char filepath[256];
    char realPathBuf[PATH_MAX];
    if (fd != -1) {
        snprintf(filepath, sizeof(filepath), "/proc/self/fd/%d", fd);
        if (realpath(filepath, realPathBuf) && contains_sensitive(realPathBuf)) {
            errno = EACCES;
            return MAP_FAILED;
        }
    }
    return origmmap_hook(addr, length, prot, flags, fd, offset);
}

HOOKAF(int, unlink_hook, const char *pathname) {
    CHECK_PATH_ORIGINAL(origunlink_hook, pathname);
}

HOOKAF(int, chdir_hook, const char *path) {
    if (contains_sensitive(path)) {
        return origchdir_hook("/");
    }
    return origchdir_hook(path);
}

HOOKAF(DIR*, opendir_hook, const char *name) {
    if (strstr(name, "/proc/") != nullptr || contains_sensitive(name)) {
        return origopendir_hook(HIDE_DIR);
    }
    return origopendir_hook(name);
}

HOOKAF(int, ptrace_hook, int request, pid_t pid, void *addr) {
    pid_t self = getpid();
    if (request == PTRACE_TRACEME && pid == self) {
        errno = EPERM;
        return -1;
    }
    return origptrace_hook(request, pid, addr);
}

HOOKAF(struct dirent*, readdir_hook, DIR *dirp) {
    struct dirent *entry;
    while ((entry = origreaddir_hook(dirp)) != nullptr) {
        if (contains_sensitive(entry->d_name)) continue;
        return entry;
    }
    return nullptr;
}

bool setupimg;

HOOKAF(void, Input, void *thiz, void *ex_ab, void *ex_ac)
{
    origInput(thiz, ex_ab, ex_ac);
    ImGui_ImplAndroid_HandleInputEvent((AInputEvent *)thiz);
}

HOOKAF(int32_t, Consume, void *thiz, void *arg1, bool arg2, long arg3, uint32_t *arg4, AInputEvent **input_event)
{
    auto result = origConsume(thiz, arg1, arg2, arg3, arg4, input_event);
    if(result != 0 || *input_event == nullptr) return result;
    ImGui_ImplAndroid_HandleInputEvent(*input_event);
    return result;
}

#include "functions.h"
#include "menu.h"

void *hack_thread(void *arg) {
    do {
        sleep(1);
        g_il2cppBaseMap = KittyMemory::getLibraryBaseMap("libil2cpp.so");
    } while (!g_il2cppBaseMap.isValid());

    KITTY_LOGI("il2cpp base: %p", (void*)(g_il2cppBaseMap.startAddress));

    Pointers();
    Hooks();

    void *accessPtr  = DobbySymbolResolver("libc.so", "access");
    void *fopenPtr   = DobbySymbolResolver("libc.so", "fopen");
    void *statPtr    = DobbySymbolResolver("libc.so", "stat");
    void *lstatPtr   = DobbySymbolResolver("libc.so", "lstat");
    void *fstatPtr   = DobbySymbolResolver("libc.so", "fstat");
    void *openPtr    = DobbySymbolResolver("libc.so", "open");
    void *lseekPtr   = DobbySymbolResolver("libc.so", "lseek");
    void *readPtr    = DobbySymbolResolver("libc.so", "read");
    void *writePtr   = DobbySymbolResolver("libc.so", "write");
    void *mmapPtr    = DobbySymbolResolver("libc.so", "mmap");
    void *unlinkPtr  = DobbySymbolResolver("libc.so", "unlink");
    void *chdirPtr   = DobbySymbolResolver("libc.so", "chdir");
    void *opendirPtr = DobbySymbolResolver("libc.so", "opendir");
    void *readdirPtr = DobbySymbolResolver("libc.so", "readdir");
    void *ptracePtr  = DobbySymbolResolver("libc.so", "ptrace");
    void *getpropPtr = DobbySymbolResolver("libc.so", "getprop");

if (accessPtr)  DobbyHook(accessPtr,  (void*)myaccess_hook,  (void**)&origaccess_hook);
if (fopenPtr)   DobbyHook(fopenPtr,   (void*)myfopen_hook,   (void**)&origfopen_hook);
if (statPtr)    DobbyHook(statPtr,    (void*)mystat_hook,    (void**)&origstat_hook);
if (lstatPtr)   DobbyHook(lstatPtr,   (void*)mylstat_hook,   (void**)&origlstat_hook);
if (fstatPtr)   DobbyHook(fstatPtr,   (void*)myfstat_hook,   (void**)&origfstat_hook);
if (openPtr)    DobbyHook(openPtr,    (void*)myopen_hook,    (void**)&origopen_hook);
if (lseekPtr)   DobbyHook(lseekPtr,   (void*)mylseek_hook,   (void**)&origlseek_hook);
if (readPtr)    DobbyHook(readPtr,    (void*)myread_hook,    (void**)&origread_hook);
if (writePtr)   DobbyHook(writePtr,   (void*)mywrite_hook,   (void**)&origwrite_hook);
if (mmapPtr)    DobbyHook(mmapPtr,    (void*)mymmap_hook,    (void**)&origmmap_hook);
if (unlinkPtr)  DobbyHook(unlinkPtr,  (void*)myunlink_hook,  (void**)&origunlink_hook);
if (chdirPtr)   DobbyHook(chdirPtr,   (void*)mychdir_hook,   (void**)&origchdir_hook);
if (opendirPtr) DobbyHook(opendirPtr, (void*)myopendir_hook, (void**)&origopendir_hook);
if (readdirPtr) DobbyHook(readdirPtr, (void*)myreaddir_hook, (void**)&origreaddir_hook);
if (ptracePtr)  DobbyHook(ptracePtr,  (void*)myptrace_hook,  (void**)&origptrace_hook);
if (getpropPtr) DobbyHook(getpropPtr, (void*)mygetprop_hook, (void**)&origgetprop_hook);

    auto eglhandle = dlopen("libunity.so", RTLD_LAZY);
    auto eglSwapBuffers = dlsym(eglhandle, "eglSwapBuffers");
    if (eglSwapBuffers)
        DobbyHook((void*)eglSwapBuffers,(void*)hook_eglSwapBuffers,
                  (void**)&old_eglSwapBuffers);

    void *sym_input = DobbySymbolResolver("/system/lib/libinput.so",
        "_ZN7android13InputConsumer21initializeMotionEventEPNS_11MotionEventEPKNS_12InputMessageE");
    if (sym_input) {
        DobbyHook(sym_input,(void*)myInput,(void**)&origInput);
    } else {
        sym_input = DobbySymbolResolver("/system/lib/libinput.so",
            "_ZN7android13InputConsumer7consumeEPNS_26InputEventFactoryInterfaceEblPjPPNS_10InputEventE");
        if(sym_input)
            DobbyHook(sym_input,(void*)myConsume,(void**)&origConsume);
    }

    LOGI("All hooks installed!");
    return nullptr;
}
