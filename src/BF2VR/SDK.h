// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#pragma once

#include <windows.h>
#include <d3d11.h>
#include <cstdint>
#include "Types.h"
#include <safetyhook.hpp>

///////////////////////////////////
// Class offsets
///////////////////////////////////

static const DWORD64 OFFSETGAMECONTEXT = 0x143DD7948;
static const DWORD64 OFFSETLOCALAIMER = 0x14406E610;

static const DWORD64 OFFSETWORLDRENDERSETTINGS = 0x143D7B068;
static const DWORD64 OFFSETDXRENDERER = 0x143FFBA28;
static const DWORD64 OFFSETGAMERENDERER = 0x143ffbe10;
static const DWORD64 OFFSETSKYBOX = 0x143F08260;

static const DWORD64 OFFSETUISETTINGS = 0x143aebb80;

///////////////////////////////////
// Function offsets
///////////////////////////////////

static const DWORD64 OFFSETCAMERA = 0x146FD3E90;
static const DWORD64 OFFSETBUILDVIEWS = 0x147c4e1a4;
static const DWORD64 OFFSETRESIZESCREEN = 0x147d94769;
static const DWORD64 OFFSETPOSE = 0x142150910;
// This is the instruction after a call to an address that dispatches render commands across the game. This specific call is for the UI
static const DWORD64 OFFSETUIDRAW = 0x140e23e28;
static const DWORD64 OFFSETGAMEPADUPDATE = 0x14774d402;
static const DWORD64 OFFSETPOST = 0x14c659a00;


///////////////////////////////////
// Utils
///////////////////////////////////

typedef Vec3 Vector3;

static inline bool isValidPtr(PVOID p) {
    return (p >= (PVOID)0x10000) && (p < ((PVOID)0x000F000000000000)) && p != nullptr &&
        !IsBadReadPtr(p, sizeof(PVOID));
}

///////////////////////////////////
// Rendering
///////////////////////////////////

class Screen {
 public:
    char pad_0000[80];  //  0x0000
    uint32_t bufferWidth;  //  0x0050
    uint32_t bufferHeight;  //  0x0054
    uint32_t anotherWidth;  //  0x0058
    uint32_t anotherHeight;  //  0x005C
};

class DXRenderer {
 public:
    static ID3D11Device* getDevice() {
        DWORD64 offset1 = *reinterpret_cast<DWORD64*>(OFFSETDXRENDERER);
        return *reinterpret_cast<ID3D11Device**>(offset1 + 0xE98);
    }
    static ID3D11DeviceContext* getContext() {
        DWORD64 offset1 = *reinterpret_cast<DWORD64*>(OFFSETDXRENDERER);
        return *reinterpret_cast<ID3D11DeviceContext**>(offset1 + 0xEA0);
    }
    static IDXGISwapChain* getSwapChain() {
        DWORD64 offset1 = *reinterpret_cast<DWORD64*>(OFFSETDXRENDERER);
        return *reinterpret_cast<IDXGISwapChain**>(offset1 + 0x338);
    }
    static Screen* getScreen() {
        DWORD64 offset1 = *reinterpret_cast<DWORD64*>(OFFSETDXRENDERER);
        return *reinterpret_cast<Screen**>(offset1 + 0xC88);
    }
};

class RenderView {
 public:
    Matrix4 transform;  // 0x0000
    char pad_0040[112];  // 0x0040
    float fov;  // 0x00B0
    char pad_00B4[20];  // 0x00B4
    float nearPlane;  // 0x00C8
    float farPlane;  // 0x00CC
    float aspectRatio;  // 0x00D0
    float orthoWidth;  // 0x00D4
    float orthoHeight;  // 0x00D8
    char pad_00DC[404];  // 0x00DC
    Matrix4 viewMatrix;  // 0x0270
    Matrix4 viewMatrixTranspose;  // 0x02B0
    Matrix4 viewMatrixInverse;  // 0x02F0
    Matrix4 projectionMatrix;  // 0x0330
    Matrix4 viewMatrixAtOrigin;  // 0x0370
    Matrix4 projectionTranspose;  // 0x03B0
    Matrix4 projectionInverse;  // 0x03F0
    Matrix4 viewProjection;  // 0x0430
    Matrix4 viewProjectionTranspose;  // 0x0470
    Matrix4 viewProjectionInverse;  // 0x04B0
};

class Skybox {
 public:
     char pad_0000[712];  // 0x0000
     bool enable;  // 0x02C8

    static Skybox* GetInstance() {
        __int64 off1 = *reinterpret_cast<__int64*>(OFFSETSKYBOX);
        if (!isValidPtr(reinterpret_cast<void*>(off1))) {
            return nullptr;
        }

        __int64 off2 = *reinterpret_cast<__int64*>(off1 + 0xc0);
        if (!isValidPtr(reinterpret_cast<void*>(off2))) {
            return nullptr;
        }

        __int64 off3 = *reinterpret_cast<__int64*>(off2 + 0x5e8);
        if (!isValidPtr(reinterpret_cast<void*>(off3))) {
            return nullptr;
        }

        Skybox* skybox = *reinterpret_cast<Skybox**>(off3 + 0x138);
        if (!isValidPtr(skybox)) {
            return nullptr;
        }
        return skybox;
    }
};

class GameRenderSettings {
 public:
    char pad_0000[40];  // 0x0000
    float resolutionScale;  // 0x0028
    char pad_002C[48];  // 0x002C
    float forceFov;  // 0x005C
    char pad_0060[1000];  // 0x0060
};

class GameRenderer {
 public:
    char pad_0000[1304];  // 0x0000
    class GameRenderSettings* gameRenderSettings;  // 0x0510
    char pad_0520[24];  // 0x0520
    class RenderView* renderView;  // 0x0538
    char pad_0540[4872];  // 0x0540

    static GameRenderer* GetInstance() {
        return *reinterpret_cast<GameRenderer**>(OFFSETGAMERENDERER);
    }
};

class WorldRenderSettings {
 public:
    char pad_0000[428];  // 0x0000
    bool motionBlurEnable;  // 0x01AC
    char pad_01AD[59];  // 0x01AD
    bool skyLightingEnable;  // 0x01E8
    char pad_01E9[403];  // 0x01E9
    float aaDisocclusionFactor;  // 0x037C
    char pad_0380[394];  // 0x0380
    bool specularLightingEnable;  // 0x050A
    char pad_050B[5];  // 0x050B
    char outdoorLightEnable;
    char pad_0511[8];  // 0x0511
    bool csLightTileCsPathEnable;  // 0x0159
    char pad_051A[89];  // 0x051A
    bool localReflectionEnable;  // 0x0573

    static WorldRenderSettings* GetInstance() {
        return *reinterpret_cast<WorldRenderSettings**>(OFFSETWORLDRENDERSETTINGS);
    }
};


class GlobalPostProcessSettings {
 public:
    char pad_0000[148];  // 0x0000
    float forceEV;  // 0x0094
    char pad_0098[44];  // 0x0098
    int32_t forceDofEnable;  // 0x00C4
    float forceDofBlurFactor;  // 0x00C8
    char pad_00CC[4];  // 0x00CC
    float forceDofFocusDistance;  // 0x00D0
    char pad_00D4[20];  // 0x00D4
    float forceSpriteDofNearStart;  // 0x00E8
    float forceSpriteDofNearEnd;  // 0x00EC
    float forceSpriteDofFarStart;  // 0x00F0
    float forceSpriteDofFarEnd;  // 0x00F4
    float forceSpriteDofBlurMax;  // 0x00F8
    char pad_00FC[284];  // 0x00FC
    bool forceEVEnable;  // 0x0218
    char pad_0219[6];  // 0x0219
    bool bloomEnable;  // 0x021F
    char pad_0220[9];  // 0x0220
    bool VignetteEnable;  // 0x229
    char pad_022A[1];  // 0x022A
    bool ColorGradingEnable;  // 0x22B
    char pad_022C[3];  // 0x022C
    bool FilmGrainEnable;  // 0x22f
    char pad_0230[5];  // 0x0230
    bool spriteDofEnable;  // 0x0235
    char pad_0236[1];  // 0x0236
    bool enableForeground;  // 0x0237
    char pad_0238[2];  // 0x0238
    bool spriteDofHalfResolutionEnable;  // 0x023A
    char pad_023B[14];  // 0x023B
    bool ScreenSpaceRaytraceEnable;  // 0x0249
    bool ScreenSpaceRaytraceDeferredResolveEnable;  //  0x024A
    bool ScreenSpaceRaytraceUseVelocityVectorsForTemporal;  //  0x024B
    bool ScreenSpaceRaytraceSeparateCoverageEnable;  //  0x024C
    bool ScreenSpaceRaytraceFullresEnable;  //  0x024D
    bool ScreenSpaceRaytraceCameraCutEnable;  //  0x024E
    bool ScreenSpaceRaytraceAsyncComputeEnable;  //  0x024F
    bool ChromaticAberrationAllowed;  // 0x25f
    bool LensDistortionAllowed;  // 0x260
    char pad_0261[3554];  // 0x0261
};

class UISettings {
 public:
    char pad_0000[68];  // 0x0000
    bool drawEnable;  // 0x0044

    static UISettings* GetInstance() {
        return *reinterpret_cast<UISettings**>(OFFSETUISETTINGS);
    }
};

///////////////////////////////////
// Game
///////////////////////////////////

class GamepadState {
 public:
    DWORD bitmask;  // 0x0000
    char pad_0004[12];  // 0x0004
    float U;  // 0x0010
    float D;  // 0x0014
    float L;  // 0x0018
    float R;  // 0x001C
    float Y;  // 0x0020
    float A;  // 0x0024
    float X;  // 0x0028
    float B;  // 0x002C
    char pad_0030[8];  // 0x0030
    float L3;  // 0x0038
    float R3;  // 0x003C
    float Menu;  // 0x0040
    float Start;  // 0x0044
    float LT;  // 0x0048
    float RT;  // 0x004C
    float LB;  // 0x0050
    float RB;  // 0x0054
    char pad_0058[184];  // 0x0058
    Vec2 LeftThumb;  // 0x0110
    Vec2 RightThumb;  // 0x0118
    char pad_0120[64];  // 0x0120
};  // Size: 0x0160

class GameSettings {
 public:
    char pad_0000[48];  // 0x0000
    char* defaultLayerInclusion;  // 0x0030
    char* level;  // 0x0038
    char pad_0040[64];  // 0x0040
};  // Size: 0x0080

class GameContext {
 public:
    char pad_0000[56];  // 0x0000
    class GameSettings* gameSettings;  // 0x0038
    char pad_0040[24];  // 0x0040
    class ClientPlayerManager* clientPlayerManager;  // 0x0058

    static GameContext* GetInstance() {
        return *reinterpret_cast<GameContext**>(OFFSETGAMECONTEXT);
    }
};  // Size: 0x0060

class ClientPlayerManager {
 public:
    char pad_0000[1384];  // 0x0000
    class ClientPlayer* localPlayer;  // 0x0568
};  // Size: 0x0570

class ClientPlayer {
 public:
    char pad_0000[24];  // 0x0000
    char* username;  // 0x0018
    char pad_0020[56];  // 0x0020
    uint32_t team;  // 0x0058
    char pad_005C[420];  // 0x005C
    class ClientControllableEntity* attachedControllable;  // 0x0200
    char pad_0208[8];  // 0x0208
    class ClientControllableEntity* controlledcontrollable;  // 0x0210
};  // Size: 0x0218

class ClientControllableEntity {
 public:
    char pad_0000[1236];  // 0x0000
    float HeightOffset;  // 0x04D4
    char pad_04D8[640];  // 0x04D8
    class ClientSoldierPrediction* clientSoldierPrediction;
};  // Size: 0x0760

class ClientSoldierPrediction {
 public:
    char pad_0000[32];  // 0x0000
    Vector3 location;  // 0x0020
    char pad_002C[8];  // 0x002C
    Vector3 velocity;  // 0x0034
};  // Size: 0x0040

class LocalAimer {
 public:
    char pad_0000[152];  // 0x0000
    class AimingComponentSwitch* aimingComponentSwitch;  // 0x0098

    static LocalAimer* GetInstance() {
        return *reinterpret_cast<LocalAimer**>(OFFSETLOCALAIMER);
    }
};  // Size: 0x00A0

class AimingComponentSwitch {
 public:
    char pad_0000[56];  // 0x0000
    class AimingComponentData* primary;  // 0x0038
    char pad_0040[104];  // 0x0040
    class AimingComponentData* secondary;  // 0x00A8
};  // Size: 0x00B0

class AimingComponentData {
 public:
    unsigned char signature[12];  // 0x0000
    char pad_000C[156];  // 0x000C
    float yaw;  // 0x00A8
    float pitch;  // 0x00AC
};  // Size: 0x00B4
