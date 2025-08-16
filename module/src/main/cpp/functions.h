#ifndef ZYCHEATS_SGUYS_FUNCTIONS_H
#define ZYCHEATS_SGUYS_FUNCTIONS_H

// here you can define variables for the patches
bool destroyAll, destroyAllAuto;

void (*DestroyPlayerObjects)(void *player, bool localOnly);
monoArray<void**> *(*get_PlayerListOthers)();

void Pointers() {
    DestroyPlayerObjects = (void (*)(void *, bool)) (g_il2cppBaseMap.startAddress + string2Offset(OBFUSCATE("0x446DAA4")));
    get_PlayerListOthers = (monoArray<void **> *(*)()) (g_il2cppBaseMap.startAddress + string2Offset(OBFUSCATE("0x446631C")));
}

void Patches() {
//    PATCH_SWITCH("0x10A69A0", "200080D2C0035FD6", showAllItems);
}

void (*old_Backend)(void *instance);
void Backend(void *instance) {
    if (instance != NULL) {
        
        if (destroyAll) {
            auto photonplayers = get_PlayerListOthers();
            for (int i = 0; i < photonplayers->getLength(); ++i) {
                auto photonplayer = photonplayers->getPointer()[i];
                DestroyPlayerObjects(photonplayer, false);
            }
            destroyAll = false;
        }
        if (destroyAllAuto) {
            auto photonplayers = get_PlayerListOthers();
            for (int i = 0; i < photonplayers->getLength(); ++i) {
                auto photonplayer = photonplayers->getPointer()[i];
                DestroyPlayerObjects(photonplayer, false);
            }
        }
        
    }
    return old_Backend(instance);
}


void* (*old_ProductDefinition)(void *instance, monoString* id, monoString* storeSpecificId, int type, bool enabled, void* payouts);
void* ProductDefinition(void *instance, monoString* id, monoString* storeSpecificId, int type, bool enabled, void* payouts) {
    if (instance != NULL) {
        LOGW("Called ProductDefinition! Here are the parameters:");
        LOGW("id: %s", id->getChars());
        LOGW("storeSpecificId: %s", storeSpecificId->getChars());
        LOGW("type: %i", type);
    }
    return old_ProductDefinition(instance, id, storeSpecificId, type, enabled, payouts);
}

void Hooks() {
    HOOK("0xE7BC74", Backend, old_Backend);
}

#endif //ZYCHEATS_SGUYS_FUNCTIONS_H
