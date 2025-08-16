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

const char * sensitiveStrings[] = {
        "/su", "superuser", "magisk", "topjohnwu",
        "luckypatcher", "chelpus", "Kinguser",
        "supersu", "busybox", "kernelsu", "daemonsu",
        "/proc/self/attr/prev", "bstfolder", "libmaa.so",
//        "arm64-v8a.so", "armeabi-v7a.so", "x86_64.so", "x86.so"
};

static int contains_sensitive(const char *path) {
    for (int i = 0; i < sizeof(sensitiveStrings)/sizeof(*sensitiveStrings); i++) {
        if (strstr(path, sensitiveStrings[i])) return 1;
    }
    return 0;
}

HOOKAF(int, access_hook, const char *filename, int mode) {
    CHECK_PATH_ORIGINAL(origaccess_hook, filename, mode);
}

HOOKAF(FILE*, fopen_hook, const char *fname, const char *mode) {
    CHECK_PATH_ORIGINAL(origfopen_hook, fname, mode);
}

HOOKAF(int, ptrace_hook, int request, pid_t pid, void *addr) {
    pid_t self = getpid();
    if (request == PTRACE_TRACEME && pid == self) {
        errno = EPERM;
        return -1;
    }
    return origptrace_hook(request, pid, addr);
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
    void *ptracePtr  = DobbySymbolResolver("libc.so", "ptrace");

    if (accessPtr)  DobbyHook(accessPtr,  (void*)myaccess_hook,  (void**)&origaccess_hook);
    if (fopenPtr)   DobbyHook(fopenPtr,   (void*)myfopen_hook,   (void**)&origfopen_hook);
    if (ptracePtr)  DobbyHook(ptracePtr,   (void*)myptrace_hook,   (void**)&origptrace_hook);

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
